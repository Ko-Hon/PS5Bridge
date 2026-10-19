import Foundation
import Darwin

@_silgen_name("flock") private func fileLock(_ fd: Int32, _ operation: Int32) -> Int32
var stopRequested = false

func secureDirectory() throws {
    if !FileManager.default.fileExists(atPath: runtimeDirectory) {
        try FileManager.default.createDirectory(atPath: runtimeDirectory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o755])
    }
    var attributes = stat()
    guard lstat(runtimeDirectory, &attributes) == 0, attributes.st_uid == 0,
          attributes.st_mode & S_IFMT == S_IFDIR, attributes.st_mode & 0o022 == 0 else {
        throw BridgeError("运行目录权限异常，已停止操作。")
    }
}

func save<T: Encodable>(_ value: T, _ name: String, permissions: Int16) throws {
    let path = runtimeDirectory + "/" + name
    try JSONEncoder().encode(value).write(to: URL(fileURLWithPath: path), options: .atomic)
    guard chmod(path, mode_t(permissions)) == 0 else { throw BridgeError("无法设置状态文件权限。") }
}

func acquireLock() throws -> Int32 {
    let fd = open(runtimeDirectory + "/lock", O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
    guard fd >= 0, fileLock(fd, LOCK_EX | LOCK_NB) == 0 else {
        if fd >= 0 { close(fd) }
        throw BridgeError("已有转发进程正在运行。")
    }
    return fd
}

func processPath(_ pid: Int32) -> String? {
    var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
    guard pid > 1, proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return nil }
    return String(cString: buffer)
}

func helperIsAlive(_ pid: Int32) -> Bool {
    guard kill(pid, 0) == 0, let path = processPath(pid) else { return false }
    return path == URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL.path
}

func parentIdentity(_ pid: Int32) throws -> (uid_t, gid_t) {
    let expected = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().appendingPathComponent("PS5VPNBridge").path
    var info = proc_bsdinfo()
    let size = MemoryLayout<proc_bsdinfo>.size
    guard processPath(pid) == expected,
          proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(size)) == Int32(size),
          info.pbi_uid >= 501 else {
        throw BridgeError("无法验证发起请求的桥接应用，请从软件界面重新启动。")
    }
    return (info.pbi_uid, info.pbi_gid)
}

struct EngineMetrics: Decodable {
    var ready: Bool
    var packets: UInt64
    var replies: UInt64
    var tcp: UInt64
    var udp: UInt64
    var failures: UInt64
    var uid: UInt32
    var uploadBytes: UInt64
    var downloadBytes: UInt64
    var uploadRate: Double
    var downloadRate: Double
    var lastClientAt: Double
    var sequence: UInt64
    var connections: [ForwardConnection]?
    var devices: [RelayDevice]?
    var ipv6Status: String?
    var ipv6Packets: UInt64?
    var ipv6Replies: UInt64?
}

final class EngineOutput {
    let lock = NSLock()
    var pending = Data()
    var metrics: EngineMetrics?
    var errors = ""
    var metricsAt: Double = 0
    func accept(_ data: Data) {
        lock.lock(); defer { lock.unlock() }
        pending.append(data)
        while let end = pending.firstIndex(of: 10) {
            let line = Data(pending[..<end]); pending.removeSubrange(...end)
            if let decoded = try? JSONDecoder().decode(EngineMetrics.self, from: line) {
                if decoded.sequence > (metrics?.sequence ?? 0) {
                    metrics = decoded; metricsAt = Date().timeIntervalSince1970
                }
            }
            else { errors = String(decoding: line.suffix(2000), as: UTF8.self) }
        }
        if pending.count > 65536 { pending.removeAll() }
    }
    func read() -> (EngineMetrics?, String, Double) {
        lock.lock(); defer { lock.unlock() }; return (metrics, errors, metricsAt)
    }
}

final class Supervisor {
    var status: BridgeStatus
    var engine: Process?
    var enginePipe: Pipe?
    var output = EngineOutput()
    var stayAwake: Process?
    var lastVPN = ""
    var lastVPNIndex: UInt32 = 0
    var traffic = TrafficLedger()

    init(config: BridgeConfiguration, parent: Int32) {
        status = BridgeStatus(phase: "starting", message: "正在启动用户态转发…", helperPID: getpid(),
                              parentPID: parent, config: config, vpn: "", packets: 0, logs: [], updated: Date().timeIntervalSince1970)
    }

    func update(_ phase: String, _ message: String, log: Bool = false) {
        status.phase = phase; status.message = message; status.updated = Date().timeIntervalSince1970
        if log {
            let formatter = DateFormatter(); formatter.dateFormat = "HH:mm:ss"
            status.logs.append("\(formatter.string(from: Date()))  \(message)")
            status.logs = Array(status.logs.suffix(30))
        }
        try? save(status, "status.json", permissions: 0o644)
    }

    func stopEngine() {
        guard let child = engine else { return }
        if child.isRunning {
            child.terminate()
            let deadline = Date().addingTimeInterval(3)
            while child.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.05) }
            if child.isRunning { kill(child.processIdentifier, SIGKILL) }
        }
        child.waitUntilExit()
        if let handle = enginePipe?.fileHandleForReading {
            handle.readabilityHandler = nil
            let fd = handle.fileDescriptor
            _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
            var buffer = [UInt8](repeating: 0, count: 4096)
            for _ in 0..<16 {
                let n = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
                if n <= 0 { break }
                output.accept(Data(buffer.prefix(n)))
            }
        }
        consumeMetrics()
        traffic.pause(); status.traffic = traffic.value
        status.connections = []
        engine = nil; enginePipe = nil
    }

    func consumeMetrics() {
        let (metrics, _, stamp) = output.read()
        guard let metrics else { return }
        traffic.consume(upload: metrics.uploadBytes, download: metrics.downloadBytes,
                        uploadRate: metrics.uploadRate, downloadRate: metrics.downloadRate, lastClientAt: metrics.lastClientAt)
        status.traffic = traffic.value; status.metricsAt = stamp; status.packets = metrics.packets
        status.connections = metrics.connections
        status.devices = metrics.devices; status.ipv6Status = metrics.ipv6Status
        status.ipv6Packets = metrics.ipv6Packets; status.ipv6Replies = metrics.ipv6Replies
    }

    func launchEngine(_ vpn: VPNInterface, uid: uid_t, gid: gid_t) throws {
        let child = Process(), pipe = Pipe()
        let path = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().appendingPathComponent("PacketRelay").path
        let encoded = try JSONEncoder().encode(status.config).base64EncodedString()
        output = EngineOutput()
        traffic.beginEngine()
        status.connections = []
        let collector = output
        pipe.fileHandleForReading.readabilityHandler = { collector.accept($0.availableData) }
        child.executableURL = URL(fileURLWithPath: path)
        child.arguments = ["--run", encoded, vpn.name, String(uid), String(gid)]
        child.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8"]
        child.standardInput = FileHandle.nullDevice; child.standardOutput = pipe; child.standardError = pipe
        try child.run(); engine = child; enginePipe = pipe
        let deadline = Date().addingTimeInterval(20)
        while Date() < deadline && !stopRequested {
            let (metrics, errors, _) = output.read()
            if let metrics, metrics.ready, metrics.uid == uid {
                status.vpn = vpn.name; lastVPN = vpn.name; lastVPNIndex = if_nametoindex(vpn.name)
                update("running", "用户态转发已开启，等待设备流量。", log: true); return
            }
            if !child.isRunning {
                stopEngine()
                throw BridgeError(errors.isEmpty ? "用户态引擎启动失败。" : errors)
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        stopEngine(); throw BridgeError("用户态引擎启动超时，已停止。")
    }

    func run() throws {
        let fd = try acquireLock(); defer { close(fd) }
        let identity = try parentIdentity(status.parentPID)
        let controlPath = runtimeDirectory + "/stop-" + String(getpid())
        _ = unlink(controlPath)
        let control = open(controlPath, O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard control >= 0 else { throw BridgeError("无法创建停止控制文件。") }
        defer { close(control); _ = unlink(controlPath) }
        guard fchown(control, identity.0, identity.1) == 0 else { throw BridgeError("无法设置停止控制文件权限。") }
        let forwarding = try checked("/usr/sbin/sysctl", ["-n", "net.inet.ip.forwarding"]).trimmingCharacters(in: .whitespacesAndNewlines)
        guard forwarding == "0" else {
            throw BridgeError("其他软件已开启系统内核转发。请先关闭 macOS 互联网共享或其他网关软件，再启动本应用；本应用不会更改该系统开关。")
        }
        if status.config.dualStack {
            let v6 = try checked("/usr/sbin/sysctl", ["-n", "net.inet6.ip6.forwarding"]).trimmingCharacters(in: .whitespacesAndNewlines)
            guard v6 == "0" else { throw BridgeError("其他软件已开启系统 IPv6 内核转发，请先关闭对应共享／网关功能。") }
        }
        let inventory = discover()
        try status.config.validate(against: inventory)
        guard let vpn = inventory.vpn else { throw BridgeError("请先连接 Shadowrocket 的 VPN 隧道。") }
        for client in status.config.clients {
            guard routeInterface(client) == status.config.interface else { throw BridgeError("设备 \(client) 不在所选局域网接口，请检查 IP。") }
        }
        let route = try checked("/sbin/route", ["-n", "get", "-ifscope", status.config.interface, "default"])
        guard firstMatch("(?m)^\\s*gateway:\\s*(\\S+)", route) .map({ !status.config.clients.contains($0) }) != false else {
            throw BridgeError("填写的是路由器 IP，请填写 PS5 的 IPv4 地址。")
        }
        let awake = Process(); awake.executableURL = URL(fileURLWithPath: "/usr/bin/caffeinate"); awake.arguments = ["-i", "-w", String(getpid())]
        try? awake.run(); stayAwake = awake
        defer {
            stopEngine()
            if awake.isRunning { awake.terminate() }
        }
        try launchEngine(vpn, uid: identity.0, gid: identity.1)
        while !stopRequested {
            Thread.sleep(forTimeInterval: 1)
            var controlByte: UInt8 = 0
            if pread(control, &controlByte, 1, 0) == 1 && controlByte == 1 { break }
            if (try? parentIdentity(status.parentPID)) == nil { break }
            let current = discover()
            guard current.interfaces.contains(where: { $0.name == status.config.interface && $0.address == status.config.gateway && $0.mask == status.config.mask }) else {
                throw BridgeError("Mac 的局域网地址发生变化，已停止转发，请更新设备设置。")
            }
            if current.vpn?.name != lastVPN || (current.vpn.map { if_nametoindex($0.name) } ?? 0) != lastVPNIndex {
                stopEngine(); lastVPN = ""; lastVPNIndex = 0
                update("paused", "VPN 已断开或切换，转发已暂停。重新连接 VPN 后会自动恢复。", log: status.phase != "paused")
                if let newVPN = current.vpn {
                    try launchEngine(newVPN, uid: identity.0, gid: identity.1)
                }
                continue
            }
            if engine?.isRunning != true {
                throw BridgeError(output.read().1.isEmpty ? "转发引擎已退出，请重新启动。" : output.read().1)
            }
            if let metrics = output.read().0 {
                consumeMetrics()
                update("running", "设备数据包 \(metrics.packets) · 回包 \(metrics.replies) · TCP \(metrics.tcp) · UDP \(metrics.udp) · 失败 \(metrics.failures)")
            } else { update("running", status.message) }
        }
        stopEngine()
        update("stopped", "转发已停止。请将 各设备的 IP 地址和 DNS 恢复为自动。", log: true)
    }
}

func stopRelay() throws {
    if let status = readStatus(), helperIsAlive(status.helperPID) {
        kill(status.helperPID, SIGTERM)
        let deadline = Date().addingTimeInterval(7)
        while helperIsAlive(status.helperPID) && Date() < deadline { Thread.sleep(forTimeInterval: 0.1) }
        guard !helperIsAlive(status.helperPID) else { throw BridgeError("进程仍在停止，请稍后重试。") }
    }
    let fd = try acquireLock(); defer { close(fd) }
    if var status = readStatus() {
        status.phase = "stopped"; status.updated = Date().timeIntervalSince1970
        status.message = "转发已停止。请将 各设备的 IP 地址和 DNS 恢复为自动。"
        try save(status, "status.json", permissions: 0o644)
    }
}

@main struct Helper {
    static func main() {
        do {
            let args = CommandLine.arguments
            guard args.count > 1 else { throw BridgeError("缺少命令。") }
            if args[1] == "--diagnose" {
                print(String(decoding: try JSONEncoder().encode(discover()), as: UTF8.self)); return
            }
            guard ["--start-userspace", "--serve-userspace", "--stop-userspace", "--probe-userspace"].contains(args[1]) else {
                throw BridgeError("旧版内核转发入口已永久移除。请使用新版用户态转发界面。")
            }
            guard geteuid() == 0 else { throw BridgeError("启动用户态转发需要 macOS 管理员验证以打开 BPF 设备。") }
            try secureDirectory()
            if args[1] == "--stop-userspace" { try stopRelay(); print("已停止用户态转发。"); return }
            guard args.count == 4, let data = Data(base64Encoded: args[2]), let parent = Int32(args[3]), parent > 1 else {
                throw BridgeError("命令参数无效。")
            }
            let config = try JSONDecoder().decode(BridgeConfiguration.self, from: data)
            try config.validate(against: discover()); _ = try parentIdentity(parent)
            if args[1] == "--probe-userspace" {
                let identity = try parentIdentity(parent)
                let forwarding = try checked("/usr/sbin/sysctl", ["-n", "net.inet.ip.forwarding"]).trimmingCharacters(in: .whitespacesAndNewlines)
                guard forwarding == "0" else { throw BridgeError("系统内核转发已被其他软件开启，请先关闭互联网共享或其他网关软件。") }
                let inventory = discover()
                guard let vpn = inventory.vpn else { throw BridgeError("请先连接 VPN。") }
                let path = URL(fileURLWithPath: args[0]).deletingLastPathComponent().appendingPathComponent("PacketRelay").path
                let result = try command(path, ["--probe", args[2], vpn.name, String(identity.0), String(identity.1)], timeout: 25)
                guard result.code == 0 else { throw BridgeError(result.output) }
                print(result.output); return
            }
            if args[1] == "--start-userspace" {
                if let status = readStatus(), helperIsAlive(status.helperPID) { throw BridgeError("转发已运行。") }
                let child = Process()
                child.executableURL = URL(fileURLWithPath: args[0]); child.arguments = ["--serve-userspace", args[2], args[3]]
                child.standardInput = FileHandle.nullDevice; child.standardOutput = FileHandle.nullDevice; child.standardError = FileHandle.nullDevice
                try child.run()
                let deadline = Date().addingTimeInterval(25)
                while Date() < deadline {
                    if let status = readStatus(), status.helperPID == child.processIdentifier {
                        if status.phase == "running" { print("用户态转发已开启。"); return }
                        if !status.running { throw BridgeError(status.message) }
                    }
                    if !child.isRunning { throw BridgeError(readStatus()?.message ?? "转发进程启动失败。") }
                    Thread.sleep(forTimeInterval: 0.1)
                }
                kill(child.processIdentifier, SIGTERM); throw BridgeError("启动超时，已请求停止。")
            }
            _ = setsid()
            signal(SIGTERM) { _ in stopRequested = true }; signal(SIGINT) { _ in stopRequested = true }; signal(SIGHUP) { _ in stopRequested = true }
            let supervisor = Supervisor(config: config, parent: parent)
            do { try supervisor.run() }
            catch { supervisor.update("error", error.localizedDescription, log: true); throw error }
        } catch {
            FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8)); exit(1)
        }
    }
}
