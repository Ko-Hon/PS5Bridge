import Foundation
import Darwin

#if BRIDGE_TESTS
let runtimeDirectory = CommandLine.arguments[1] + "/runtime"
var testCommandHandler: ((String, [String]) throws -> CommandResult)?
#else
let runtimeDirectory = "/var/run/com.local.ps5vpnbridge.userspace"
#endif

struct BridgeError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

struct CommandResult {
    let code: Int32
    let output: String
}

@discardableResult
func command(_ path: String, _ arguments: [String], timeout: Double = 8) throws -> CommandResult {
    #if BRIDGE_TESTS
    if let handler = testCommandHandler { return try handler(path, arguments) }
    #endif
    let process = Process()
    process.executableURL = URL(fileURLWithPath: path); process.arguments = arguments
    let pipe = Pipe(); process.standardOutput = pipe; process.standardError = pipe
    try process.run()
    let fd = pipe.fileHandleForReading.fileDescriptor
    _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
    var collected = Data()
    var buffer = [UInt8](repeating: 0, count: 16384)
    func drain() {
        for _ in 0..<64 {
            let n = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
            if n > 0 { if collected.count < 4 * 1024 * 1024 { collected.append(contentsOf: buffer.prefix(n)) }; continue }
            if n < 0 && errno == EINTR { continue }
            break
        }
    }
    let deadline = Date().addingTimeInterval(timeout)
    while process.isRunning && Date() < deadline { drain(); Thread.sleep(forTimeInterval: 0.02) }
    if process.isRunning {
        process.terminate(); Thread.sleep(forTimeInterval: 0.15)
        if process.isRunning { kill(process.processIdentifier, SIGKILL) }
        process.waitUntilExit(); drain(); try? pipe.fileHandleForReading.close()
        throw BridgeError("命令超时：\(URL(fileURLWithPath: path).lastPathComponent)")
    }
    process.waitUntilExit(); drain(); try? pipe.fileHandleForReading.close()
    return CommandResult(code: process.terminationStatus, output: String(decoding: collected, as: UTF8.self))
}

@discardableResult
func checked(_ path: String, _ arguments: [String]) throws -> String {
    let result = try command(path, arguments)
    guard result.code == 0 else { throw BridgeError("\(URL(fileURLWithPath: path).lastPathComponent)：\(result.output.trimmingCharacters(in: .whitespacesAndNewlines))") }
    return result.output
}

func firstMatch(_ pattern: String, _ text: String, group: Int = 1) -> String? {
    guard let regex = try? NSRegularExpression(pattern: pattern),
          let match = regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)),
          group < match.numberOfRanges, let range = Range(match.range(at: group), in: text) else { return nil }
    return String(text[range])
}

func ipv4(_ text: String) -> UInt32? {
    let parts = text.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4 else { return nil }
    var result: UInt32 = 0
    for part in parts {
        guard !part.isEmpty, part.allSatisfy({ $0.isASCII && $0.isNumber }),
              part.count == 1 || part.first != "0", let number = UInt32(part), number <= 255 else { return nil }
        result = (result << 8) | number
    }
    return result
}

func ipString(_ value: UInt32) -> String {
    [24, 16, 8, 0].map { String((value >> $0) & 255) }.joined(separator: ".")
}

func isPrivate(_ value: UInt32) -> Bool {
    value & 0xff000000 == 0x0a000000 || value & 0xfff00000 == 0xac100000 || value & 0xffff0000 == 0xc0a80000
}

struct LANInterface: Codable, Equatable, Identifiable {
    let name: String
    let title: String
    let address: String
    let mask: String
    var id: String { name }
    var subnet: String {
        guard let ip = ipv4(address), let maskValue = ipv4(mask) else { return "" }
        return "\(ipString(ip & maskValue))/\(maskValue.nonzeroBitCount)"
    }
}

struct VPNInterface: Codable, Equatable {
    let name: String
    let address: String
}

struct Inventory: Codable {
    var interfaces: [LANInterface]
    var vpn: VPNInterface?
    var routeInterface: String
}

func routeInterface(_ target: String) -> String? {
    guard let result = try? command("/sbin/route", ["-n", "get", target]), result.code == 0 else { return nil }
    return firstMatch("(?m)^\\s*interface:\\s*(\\S+)", result.output)
}

func discover() -> Inventory {
    let text = (try? checked("/sbin/ifconfig", ["-a"])) ?? ""
    let hardware = (try? checked("/usr/sbin/networksetup", ["-listallhardwareports"])) ?? ""
    var titles: [String: String] = [:]
    var title = ""
    for line in hardware.components(separatedBy: .newlines) {
        if line.hasPrefix("Hardware Port: ") { title = String(line.dropFirst(15)) }
        if line.hasPrefix("Device: ") { titles[String(line.dropFirst(8))] = title }
    }
    var interfaces: [LANInterface] = []
    var tunnels: [String: String] = [:]
    var name = ""
    for line in text.components(separatedBy: .newlines) {
        if let parsed = firstMatch("^([a-z][a-z0-9]*):", line) { name = parsed }
        guard let ip = firstMatch("^\\s+inet (\\d+\\.\\d+\\.\\d+\\.\\d+) ", line) else { continue }
        if name.hasPrefix("utun") { tunnels[name] = ip; continue }
        guard let title = titles[name], let address = ipv4(ip), isPrivate(address),
              let maskHex = firstMatch("netmask 0x([0-9a-fA-F]+)", line), let mask = UInt32(maskHex, radix: 16) else { continue }
        interfaces.append(LANInterface(name: name, title: title, address: ip, mask: ipString(mask)))
    }
    let routed = routeInterface("1.1.1.1") ?? ""
    let vpn = tunnels[routed].map { VPNInterface(name: routed, address: $0) }
    return Inventory(interfaces: interfaces.sorted { a, b in
        let aWiFi = a.title.lowercased().contains("wi-fi"), bWiFi = b.title.lowercased().contains("wi-fi")
        return aWiFi != bWiFi ? aWiFi : a.name < b.name
    }, vpn: vpn, routeInterface: routed)
}

struct BridgeConfiguration: Codable, Equatable {
    let interface: String
    let gateway: String
    let mask: String
    let client: String
    var subnet: String { LANInterface(name: interface, title: "", address: gateway, mask: mask).subnet }

    func validate(against inventory: Inventory) throws {
        guard firstMatch("^([a-z][a-z0-9]{0,15})$", interface) != nil,
              inventory.interfaces.contains(where: { $0.name == interface && $0.address == gateway && $0.mask == mask }) else {
            throw BridgeError("Mac 的网络已变化，请刷新后重新选择与 PS5 相同的 Wi-Fi／局域网。")
        }
        guard let macIP = ipv4(gateway), let clientIP = ipv4(client), let netmask = ipv4(mask), isPrivate(clientIP) else {
            throw BridgeError("请输入 PS5 当前的局域网 IPv4 地址，例如 192.168.50.100。")
        }
        let inverse = ~netmask
        guard netmask.nonzeroBitCount >= 8, netmask.nonzeroBitCount <= 30, inverse & (inverse &+ 1) == 0 else {
            throw BridgeError("当前子网掩码不适用于此网关模式。")
        }
        guard macIP & netmask == clientIP & netmask else { throw BridgeError("PS5 和 Mac 必须处于同一 IPv4 子网。") }
        guard clientIP != macIP, clientIP & inverse != 0, clientIP & inverse != inverse else {
            throw BridgeError("PS5 的 IP 不能是 Mac 地址、网络地址或广播地址。")
        }
        guard !inventory.interfaces.contains(where: { $0.address == client }) else { throw BridgeError("这个 IP 已由 Mac 使用，请填写 PS5 的 IP。") }
    }
}

struct BridgeStatus: Codable {
    var phase: String
    var message: String
    var helperPID: Int32
    var parentPID: Int32
    var config: BridgeConfiguration
    var vpn: String
    var packets: UInt64
    var logs: [String]
    var updated: Double
    var traffic: BridgeTraffic? = nil
    var metricsAt: Double? = nil
    var connections: [ForwardConnection]? = nil
    var running: Bool { ["starting", "running", "paused", "stopping"].contains(phase) }
}

struct BridgeTraffic: Codable {
    var uploadBytes: UInt64 = 0
    var downloadBytes: UInt64 = 0
    var uploadRate: Double = 0
    var downloadRate: Double = 0
    var lastClientAt: Double = 0
    var totalBytes: UInt64 { saturatedAdd(uploadBytes, downloadBytes) }
}

func saturatedAdd(_ a: UInt64, _ b: UInt64) -> UInt64 {
    let result = a.addingReportingOverflow(b)
    return result.overflow ? .max : result.partialValue
}

struct TrafficLedger {
    private(set) var value = BridgeTraffic()
    private var previousUpload: UInt64 = 0
    private var previousDownload: UInt64 = 0
    mutating func beginEngine() { previousUpload = 0; previousDownload = 0; pause() }
    mutating func pause() { value.uploadRate = 0; value.downloadRate = 0 }
    mutating func consume(upload: UInt64, download: UInt64, uploadRate: Double, downloadRate: Double, lastClientAt: Double) {
        value.uploadBytes = saturatedAdd(value.uploadBytes, upload >= previousUpload ? upload - previousUpload : 0)
        value.downloadBytes = saturatedAdd(value.downloadBytes, download >= previousDownload ? download - previousDownload : 0)
        previousUpload = max(previousUpload, upload); previousDownload = max(previousDownload, download)
        value.uploadRate = uploadRate.isFinite ? max(0, uploadRate) : 0
        value.downloadRate = downloadRate.isFinite ? max(0, downloadRate) : 0
        if lastClientAt.isFinite { value.lastClientAt = max(value.lastClientAt, lastClientAt) }
    }
}

struct ConnectionHealth: Codable {
    var config: BridgeConfiguration
    var vpn: String
    var lanReady: Bool
    var ps5Reachable: Bool
    var ps5Latency: Double
    var vpnReachable: Bool
    var googlePing: Bool
    var googleLatency: Double
    var vpnDetail: String
    var checkedAt: Double
    var googleHTTPSLatency: Double? = nil
    var serverPings: [ServerPing]? = nil
}

struct ForwardConnection: Codable, Identifiable {
    var id: String
    var `protocol`: String
    var ip: String
    var port: UInt16
    var active: Int
    var connectLatency: Double?
    var dialFailed: Bool
    var updated: Double
    var domain: String? = nil
    var domainSource: String? = nil
    var aliases: [String]? = nil
    var serverName: String { domain?.isEmpty == false ? domain! : ip }
    var serverDetail: String {
        let names = (aliases ?? []).joined(separator: "、")
        return "\(ip):\(port)\n\(domainSource ?? "尚未识别域名")\(names.isEmpty ? "" : " · " + names)"
    }
}

struct ServerPing: Codable {
    var ip: String
    var latency: Double?
    var checkedAt: Double
}

func formatLatency(_ milliseconds: Double?) -> String {
    guard let n = milliseconds, n.isFinite, n >= 0 else { return "—" }
    return n < 1 ? "<1 ms" : String(format: "%.1f ms", n)
}

struct VPNHealthTracker {
    private var config: BridgeConfiguration?
    private var vpn = ""
    private var failedChecks = 0
    private var lastSuccess: Double = 0
    mutating func record(_ report: ConnectionHealth) {
        if config != report.config || vpn != report.vpn {
            config = report.config; vpn = report.vpn; failedChecks = 0; lastSuccess = 0
        }
        if report.vpnReachable { failedChecks = 0; lastSuccess = report.checkedAt }
        else { failedChecks = min(2, failedChecks + 1) }
    }
    func online(config target: BridgeConfiguration?, vpn targetVPN: String, now: Double) -> Bool {
        !targetVPN.isEmpty && config == target && vpn == targetVPN && failedChecks < 2 && recently(lastSuccess, now: now, seconds: 20)
    }
}

func recently(_ stamp: Double, now: Double = Date().timeIntervalSince1970, seconds: Double) -> Bool {
    stamp > 0 && now - stamp >= -2 && now - stamp <= seconds
}

func formatTraffic(_ bytes: Double) -> String {
    let amount = bytes.isFinite ? max(0, bytes) : 0
    let units = ["B", "KB", "MB", "GB", "TB", "PB", "EB"]
    var value = amount; var index = 0
    while value >= 1024 && index < units.count - 1 { value /= 1024; index += 1 }
    return index == 0 ? "\(Int(value)) B" : String(format: "%.2f %@", value, units[index])
}

func readStatus() -> BridgeStatus? {
    guard let data = try? Data(contentsOf: URL(fileURLWithPath: runtimeDirectory + "/status.json")) else { return nil }
    return try? JSONDecoder().decode(BridgeStatus.self, from: data)
}

func requestRelayStop(_ status: BridgeStatus) throws {
    guard status.helperPID > 1 else { throw BridgeError("无效的转发进程。") }
    let path = runtimeDirectory + "/stop-" + String(status.helperPID)
    let fd = open(path, O_WRONLY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { throw BridgeError("转发进程已退出；可以关闭并重新打开应用。") }
    defer { close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
          info.st_uid == getuid(), info.st_mode & 0o777 == 0o600 else {
        throw BridgeError("停止控制文件权限异常。")
    }
    var value: UInt8 = 1
    guard pwrite(fd, &value, 1, 0) == 1 else { throw BridgeError("停止请求写入失败。") }
}

func ps5Settings(_ config: BridgeConfiguration) -> String {
    """
    PS5：设置 → 网络 → 设置 → 设定互联网连接 → 当前 Wi-Fi → 高级设定
    IP 地址设定：手动
    IPv4 地址：\(config.client)
    子网掩码：\(config.mask)
    默认网关：\(config.gateway)
    首选 DNS：1.1.1.1
    备用 DNS：8.8.8.8
    MTU：自动
    代理服务器：不使用
    
    Mac 和 PS5 保持连接同一个路由器的普通 Wi-Fi，避免访客网络／客户端隔离。
    本工具转发 IPv4。若 PS5 使用 IPv6，它可能直接经过路由器；要全部走此网关，请关闭路由器该网络的 IPv6。
    停止使用后，将 PS5 的 IP 地址设定和 DNS 设定恢复为自动。
    """
}
