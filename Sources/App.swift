import AppKit
import SwiftUI
import UniformTypeIdentifiers

@MainActor final class BridgeModel: ObservableObject {
    @Published var inventory = Inventory(interfaces: [], vpn: nil, routeInterface: "")
    @Published var interfaceName = UserDefaults.standard.string(forKey: "interface") ?? ""
    @Published var clientIP = UserDefaults.standard.string(forKey: "clientIP") ?? ""
    @Published var status: BridgeStatus?
    @Published var busy = false
    @Published var errorMessage: String?
    @Published var showHelp = false
    @Published var showDiagnostics = false
    @Published var selectedPage: BridgePage = .monitor
    @Published var health: ConnectionHealth?
    @Published var healthChecking = false
    @Published var tickTime = Date().timeIntervalSince1970
    @Published private var vpnTracker = VPNHealthTracker()
    private var refreshing = false
    private var timer: Timer?
    private var lastInventoryTime: Double = 0
    private var lastHealthTime: Double = 0

    init() {
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
    }

    var selectedLAN: LANInterface? { inventory.interfaces.first { $0.name == interfaceName } }
    var active: Bool { status?.running == true && Date().timeIntervalSince1970 - (status?.updated ?? 0) < 15 }
    var config: BridgeConfiguration? {
        guard let lan = selectedLAN else { return nil }
        return BridgeConfiguration(interface: lan.name, gateway: lan.address, mask: lan.mask,
                                   client: clientIP.trimmingCharacters(in: .whitespacesAndNewlines))
    }
    var displayedConfig: BridgeConfiguration? { active ? status?.config : config }
    var traffic: BridgeTraffic { status?.traffic ?? BridgeTraffic() }
    var ratesFresh: Bool { active && status?.phase == "running" && recently(status?.metricsAt ?? 0, now: tickTime, seconds: 3.5) }
    var connections: [ForwardConnection] { ratesFresh ? Array((status?.connections ?? []).prefix(12)) : [] }
    var ps5LatencyText: String {
        guard let h = matchedHealth else { return "—" }
        return h.ps5Reachable ? formatLatency(h.ps5Latency) : "无响应"
    }
    var googleLatencyText: String {
        guard let h = matchedHealth else { return "—" }
        return h.googlePing ? formatLatency(h.googleLatency) : "无响应"
    }
    func serverLatencyText(_ ip: String) -> String {
        guard let row = matchedHealth?.serverPings?.first(where: { $0.ip == ip }),
              recently(row.checkedAt, now: tickTime, seconds: 15) else { return "待检测" }
        return row.latency == nil ? "无响应" : formatLatency(row.latency)
    }
    var matchedHealth: ConnectionHealth? {
        guard let health, health.config == displayedConfig, health.vpn == (inventory.vpn?.name ?? ""),
              recently(health.checkedAt, now: tickTime, seconds: 15) else { return nil }
        return health
    }
    var recentPS5Traffic: Bool { status?.config == displayedConfig && recently(traffic.lastClientAt, now: tickTime, seconds: 30) }
    var ps5Online: Bool { matchedHealth?.ps5Reachable == true || recentPS5Traffic }
    var macOnline: Bool { selectedLAN != nil && ratesFresh && matchedHealth?.lanReady != false }
    var vpnOnline: Bool {
        matchedHealth != nil && vpnTracker.online(config: displayedConfig, vpn: inventory.vpn?.name ?? "", now: tickTime)
    }
    var ps5Detail: String {
        if recentPS5Traffic { return "已通讯" }
        if matchedHealth?.ps5Reachable == true { return "已连接" }
        return healthChecking && matchedHealth == nil ? "检测中" : "暂无响应"
    }
    var macDetail: String {
        if macOnline { return "转发正常" }
        if selectedLAN == nil || matchedHealth?.lanReady == false { return "网络未连接" }
        if active { return status?.phase == "paused" ? "转发已暂停" : "引擎检测中" }
        return "未启动转发"
    }
    var vpnDetail: String {
        if inventory.vpn == nil { return "未连接" }
        if let matchedHealth {
            if vpnOnline && !matchedHealth.vpnReachable { return "Google 复核中" }
            if matchedHealth.vpnReachable {
                return "Google 已连通"
            }
            return "Google 不可达"
        }
        return healthChecking ? "检测中" : "等待检测"
    }
    var validation: String? {
        guard let config else { return "请先连接与 PS5 相同的 Wi-Fi。" }
        if config.client.isEmpty { return "在 PS5「网络 → 连接状态 → 查看连接状态」中查看 IPv4 地址。" }
        do { try config.validate(against: inventory); return nil }
        catch { return error.localizedDescription }
    }
    var phaseTitle: String {
        if busy { return "正在处理…" }
        if active { return status?.phase == "paused" ? "转发已暂停" : "IPv4 转发已开启" }
        return inventory.vpn == nil ? "请先连接 Shadowrocket" : "准备就绪"
    }
    var phaseColor: Color {
        if status?.phase == "error" { return .orange }
        return active && status?.phase == "running" ? .green : (inventory.vpn == nil ? .orange : .blue)
    }

    func refresh() {
        guard !refreshing else { return }
        tickTime = Date().timeIntervalSince1970
        let discoverNow = tickTime - lastInventoryTime >= 3 || inventory.interfaces.isEmpty
        if discoverNow { lastInventoryTime = tickTime }
        let cachedInventory = inventory
        refreshing = true
        Task {
            let (freshInventory, freshStatus) = await Task.detached { (discoverNow ? discover() : cachedInventory, readStatus()) }.value
            inventory = freshInventory; status = freshStatus
            if !inventory.interfaces.contains(where: { $0.name == interfaceName }) { interfaceName = inventory.interfaces.first?.name ?? "" }
            if active, let current = status { clientIP = current.config.client; interfaceName = current.config.interface }
            refreshing = false
            refreshHealth()
        }
    }

    func refreshHealth() {
        guard !healthChecking, tickTime - lastHealthTime >= 5, let target = displayedConfig else { return }
        let vpn = inventory.vpn?.name ?? ""
        let path = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/PacketRelay").path
        guard let data = try? JSONEncoder().encode(target) else { return }
        let encoded = data.base64EncodedString()
        let targets = (try? JSONEncoder().encode(connections.map(\.ip)))?.base64EncodedString() ?? ""
        healthChecking = true; lastHealthTime = tickTime
        Task {
            let report = await Task.detached { () -> ConnectionHealth? in
                guard let result = try? command(path, ["--health", encoded, vpn, targets], timeout: 9), result.code == 0 else { return nil }
                return try? JSONDecoder().decode(ConnectionHealth.self, from: Data(result.output.utf8))
            }.value
            if let report, report.config == displayedConfig, report.vpn == (inventory.vpn?.name ?? "") {
                vpnTracker.record(report); health = report
            }
            healthChecking = false
        }
    }

    func begin() {
        guard !busy, let config else { return }
        do {
            try config.validate(against: inventory)
            guard inventory.vpn != nil else { throw BridgeError("请先连接 Shadowrocket，并确保 Mac 的网络出口已就绪。") }
            let encoded = try JSONEncoder().encode(config).base64EncodedString()
            UserDefaults.standard.set(config.client, forKey: "clientIP")
            UserDefaults.standard.set(config.interface, forKey: "interface")
            executePrivileged(["--start-userspace", encoded, String(getpid())])
        } catch { errorMessage = error.localizedDescription }
    }

    func probe() {
        guard !busy, let config else { return }
        do {
            try config.validate(against: inventory)
            executePrivileged(["--probe-userspace", try JSONEncoder().encode(config).base64EncodedString(), String(getpid())])
        } catch { errorMessage = error.localizedDescription }
    }

    func stop() {
        guard !busy, let current = status else { return }
        do { try requestRelayStop(current) } catch { errorMessage = error.localizedDescription; return }
        busy = true
        Task {
            let stopped = await Task.detached {
                let deadline = Date().addingTimeInterval(9)
                while Date() < deadline {
                    if let fresh = readStatus(), fresh.helperPID == current.helperPID && !fresh.running { return true }
                    try? await Task.sleep(nanoseconds: 100_000_000)
                }
                return false
            }.value
            busy = false
            if !stopped { errorMessage = "停止尚未完成。关闭应用也会让后台转发自动退出。" }
            refresh()
        }
    }

    func executePrivileged(_ arguments: [String]) {
        guard !busy else { return }
        let helper = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/BridgeHelper").path
        guard FileManager.default.isExecutableFile(atPath: helper) else { errorMessage = "应用内缺少转发组件，请重新构建完整应用。"; return }
        func quoteShell(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'" }
        let shellCommand = ([helper] + arguments).map(quoteShell).joined(separator: " ")
        let appleString = shellCommand.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        let script = "do shell script \"\(appleString)\" with administrator privileges with prompt \"游界桥需要打开指定 PS5 的网络捕获接口。\""
        busy = true
        Task {
            let result: Result<CommandResult, Error> = await Task.detached {
                Result { try command("/usr/bin/osascript", ["-e", script], timeout: 180) }
            }.value
            busy = false
            switch result {
            case .success(let response):
                if arguments.first == "--probe-userspace" && response.code == 0 { errorMessage = response.output }
                if response.code != 0 {
                    errorMessage = response.output.contains("-128") ? "已取消管理员验证，未启动新的转发。" : response.output
                }
            case .failure(let error): errorMessage = error.localizedDescription
            }
            refresh()
        }
    }

    func copySettings() {
        guard let config = displayedConfig else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(ps5Settings(config), forType: .string)
    }

    func exportDiagnostics() {
        let panel = NSSavePanel(); panel.nameFieldStringValue = "游界桥-诊断.txt"
        panel.allowedContentTypes = [.plainText]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let inventoryJSON = (try? JSONEncoder().encode(inventory)).map { String(decoding: $0, as: UTF8.self) } ?? ""
        let connectionText = connections.map { "\($0.protocol) \($0.serverName):\($0.port) [\($0.ip) · \($0.domainSource ?? "IP")] · 活跃 \($0.active) · Ping \(serverLatencyText($0.ip)) · TCP 建连 \(formatLatency($0.connectLatency))" }.joined(separator: "\n")
        let text = "游界桥 2.5\n\(Date())\n\n引擎：用户态 TCP／UDP；指定网络出口绑定；不启用系统内核转发\n\n网络检测：\n\(inventoryJSON)\n\n状态灯：PS5 \(ps5Detail)；Mac \(macDetail)；网络出口 \(matchedHealth?.vpnDetail ?? vpnDetail)\n\n延迟：Mac → PS5 Ping \(ps5LatencyText)；经网络出口 → 8.8.8.8 Ping \(googleLatencyText)；Google HTTPS \(formatLatency(matchedHealth?.googleHTTPSLatency))\n\n目标连接（最多 12 个；Ping 可能由网络出口代答；TCP 建连不是游戏 RTT）：\n\(connectionText)\n\n本次流量：上传 \(traffic.uploadBytes) B；下载 \(traffic.downloadBytes) B；合计 \(traffic.totalBytes) B\n\n状态：\n\(status?.message ?? "尚未启动")\n\n日志：\n\(status?.logs.joined(separator: "\n") ?? "无")"
        do { try text.write(to: url, atomically: true, encoding: .utf8) }
        catch { errorMessage = error.localizedDescription }
    }
}

struct CollapsibleCard<Content: View>: View {
    let title: String
    let symbol: String
    let summary: String
    let content: Content
    @AppStorage private var expanded: Bool
    init(_ title: String, symbol: String, key: String, summary: String = "", @ViewBuilder content: () -> Content) {
        self.title = title; self.symbol = symbol; self.summary = summary; self.content = content()
        _expanded = AppStorage(wrappedValue: false, "card.\(key).expanded")
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                expanded.toggle()
            } label: {
                HStack(spacing: 10) {
                    Image(systemName: expanded ? "chevron.down" : "chevron.right")
                        .font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                        .frame(width: 12).accessibilityHidden(true)
                    Label(title, systemImage: symbol).font(.headline)
                    Spacer(minLength: 10)
                    if !summary.isEmpty { Text(summary).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle) }
                }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(20).contentShape(Rectangle())
            }
                .buttonStyle(.plain)
                .accessibilityLabel(summary.isEmpty ? title : "\(title)，\(summary)")
                .accessibilityValue(expanded ? "已展开" : "已折叠")
                .accessibilityHint(expanded ? "折叠此卡片" : "展开此卡片")
            if expanded {
                VStack(alignment: .leading, spacing: 14) { content }
                    .padding(.horizontal, 20).padding(.bottom, 20)
            }
        }
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 16))
            .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.primary.opacity(0.06)))
    }
}

struct SettingRow: View {
    let label: String
    let value: String
    var emphasis = false
    var body: some View {
        HStack {
            Text(label).foregroundStyle(.secondary)
            Spacer()
            Text(value).font(.system(size: 14, weight: emphasis ? .bold : .medium, design: .monospaced))
                .foregroundStyle(emphasis ? Color.blue : Color.primary).textSelection(.enabled)
        }.padding(.vertical, 2)
    }
}

struct ConnectionLamp: View {
    let title: String
    let online: Bool
    let detail: String
    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 8) {
                Circle().fill(online ? Color.green : Color.red).frame(width: 11, height: 11)
                Text(title).font(.headline)
            }
            Text(detail).font(.caption).foregroundStyle(.secondary).lineLimit(1).minimumScaleFactor(0.75)
        }.frame(maxWidth: .infinity, alignment: .leading).padding(14)
            .background((online ? Color.green : Color.red).opacity(0.06), in: RoundedRectangle(cornerRadius: 11))
            .accessibilityElement(children: .combine)
            .accessibilityLabel("\(title)：\(online ? "已连接" : "未连接")，\(detail)")
    }
}

struct TrafficMetric: View {
    let title: String
    let value: String
    let subtitle: String
    let symbol: String
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: symbol).font(.callout).foregroundStyle(.secondary)
            Text(value).font(.system(size: 25, weight: .semibold, design: .rounded)).monospacedDigit().lineLimit(1).minimumScaleFactor(0.6)
            Text(subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1).minimumScaleFactor(0.7)
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
}

enum BridgePage: Hashable { case monitor, settings }

struct BridgeView: View {
    @StateObject var model = BridgeModel()
    private static let logo = Bundle.main.url(forResource: "Logo", withExtension: "png")
        .flatMap { NSImage(contentsOf: $0) } ?? NSImage(named: NSImage.applicationIconName) ?? NSImage()
    var body: some View {
        VStack(spacing: 0) {
            VStack(spacing: 16) { header; controls }
                .padding(26).padding(.bottom, -10).frame(maxWidth: 1020).frame(maxWidth: .infinity)
            Divider()
            switch model.selectedPage {
            case .monitor: monitorPage
            case .settings: settingsPage
            }
        }.background(Color(nsColor: .windowBackgroundColor))
            .frame(minWidth: 870, minHeight: 680)
            .alert("游界桥", isPresented: Binding(get: { model.errorMessage != nil }, set: { if !$0 { model.errorMessage = nil } })) {
                Button("好", role: .cancel) { model.errorMessage = nil }
            } message: { Text(model.errorMessage ?? "") }
            .sheet(isPresented: $model.showHelp) { helpSheet }
    }

    private var monitorPage: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                connectionCard
                trafficCard
                latencyCard
                serverCard
                if model.validation != nil {
                    Button("前往设置完成网络配置") { model.selectedPage = .settings }
                        .buttonStyle(.link)
                }
            }.padding(26).frame(maxWidth: 1020).frame(maxWidth: .infinity)
        }.id(BridgePage.monitor)
    }

    private var settingsPage: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(alignment: .top, spacing: 16) { macCard; ps5Card }
                hintsCard
                diagnosticsCard
                Text("停止使用后，将 PS5 的 IP 地址和 DNS 恢复为自动。建议在路由器中给 Mac 和 PS5 保留当前 IPv4 地址。")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }.padding(26).frame(maxWidth: 1020).frame(maxWidth: .infinity)
        }.id(BridgePage.settings)
    }

    private var header: some View {
        HStack(spacing: 16) {
            Image(nsImage: Self.logo).resizable().interpolation(.high).scaledToFit()
                .frame(width: 72, height: 72)
                .accessibilityLabel("手柄连接全球网络")
            VStack(alignment: .leading, spacing: 5) {
                Text("游界桥").font(.system(size: 27, weight: .bold))
                Text("通过 Mac 连接全球游戏网络 · 2.5").foregroundStyle(.secondary)
            }
            Spacer()
            Picker("页面", selection: $model.selectedPage) {
                Text("监控").tag(BridgePage.monitor)
                Text("设置").tag(BridgePage.settings)
            }.pickerStyle(.segmented).labelsHidden().frame(width: 220)
                .accessibilityLabel("页面切换")
            Button { model.showHelp = true } label: { Image(systemName: "questionmark.circle").font(.title2) }
                .buttonStyle(.plain).help("使用说明")
        }.padding(.bottom, 2)
    }

    private var controls: some View {
        HStack(spacing: 12) {
            Circle().fill(model.phaseColor).frame(width: 10, height: 10)
            Text(model.phaseTitle).font(.headline)
            Spacer()
            if let vpn = model.inventory.vpn {
                Text("网络出口 · \(vpn.name)").font(.callout).foregroundStyle(.secondary)
            } else {
                Button("打开 Shadowrocket") { NSWorkspace.shared.open(URL(fileURLWithPath: "/Applications/Shadowrocket.app")) }
            }
            if model.busy { ProgressView().controlSize(.small) }
            if model.active {
                Button(action: model.stop) { Label("停止转发", systemImage: "stop.fill").frame(width: 120) }
                    .controlSize(.large).disabled(model.busy)
            } else {
                Button(action: model.begin) { Label("开始转发", systemImage: "play.fill").frame(width: 120) }
                    .buttonStyle(.borderedProminent).controlSize(.large)
                    .disabled(model.busy || model.validation != nil || model.inventory.vpn == nil)
            }
        }.padding(.vertical, 5)
    }

    private var connectionCard: some View {
        CollapsibleCard("连接状态", symbol: "network", key: "connections", summary: "\([model.ps5Online, model.macOnline, model.vpnOnline].filter { $0 }.count)/3 已连接") {
            HStack(spacing: 10) {
                ConnectionLamp(title: "PS5", online: model.ps5Online, detail: model.ps5Detail)
                    .help("局域网 Ping 可达，或最近 30 秒收到 PS5 转发数据时显示绿色。")
                Image(systemName: "arrow.right").foregroundStyle(.tertiary)
                ConnectionLamp(title: "Mac", online: model.macOnline, detail: model.macDetail)
                    .help("所选局域网有效且转发引擎正常更新状态时显示绿色。")
                Image(systemName: "arrow.right").foregroundStyle(.tertiary)
                ConnectionLamp(title: "网络出口", online: model.vpnOnline, detail: model.vpnDetail)
                    .help(model.matchedHealth?.vpnDetail ?? "Google Ping 与 HTTPS 连通性检测。")
            }
            if let status = model.status {
                Text(status.running && !model.active ? "上次会话已结束，可以重新开始。" : status.message)
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Text("启动需要管理员验证，停止无需再次输入密码。转发期间保持 Mac 开机。")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private var trafficCard: some View {
        CollapsibleCard("速率与流量", symbol: "arrow.up.arrow.down", key: "traffic",
                        summary: "↑ \(formatTraffic(model.ratesFresh ? model.traffic.uploadRate : 0))/s  ↓ \(formatTraffic(model.ratesFresh ? model.traffic.downloadRate : 0))/s · \(formatTraffic(Double(model.traffic.totalBytes)))") {
            HStack(alignment: .top, spacing: 22) {
                TrafficMetric(title: "上传速率", value: formatTraffic(model.ratesFresh ? model.traffic.uploadRate : 0) + "/s",
                              subtitle: "累计上传 " + formatTraffic(Double(model.traffic.uploadBytes)), symbol: "arrow.up")
                Divider()
                TrafficMetric(title: "下载速率", value: formatTraffic(model.ratesFresh ? model.traffic.downloadRate : 0) + "/s",
                              subtitle: "累计下载 " + formatTraffic(Double(model.traffic.downloadBytes)), symbol: "arrow.down")
                Divider()
                TrafficMetric(title: "总流量", value: formatTraffic(Double(model.traffic.totalBytes)), subtitle: "本次转发累计", symbol: "arrow.up.arrow.down")
            }.fixedSize(horizontal: false, vertical: true)
            Text("每秒更新 · 上传／下载以 PS5 为参照 · 出口重连不会清零")
                .font(.caption).foregroundStyle(.secondary)
                .help("统计本次启动转发后 PS5 与 Mac 间的 IPv4 包长，含协议头，不含以太网和隧道外层开销；检测流量不计入。停止后保留结果，再次启动重新累计。")
        }
    }

    private var latencyCard: some View {
        CollapsibleCard("通讯延迟", symbol: "waveform.path.ecg", key: "latency", summary: "PS5 \(model.ps5LatencyText) · Google HTTPS \(formatLatency(model.matchedHealth?.googleHTTPSLatency))") {
            HStack(alignment: .top, spacing: 22) {
                TrafficMetric(title: "PS5 Ping", value: model.ps5LatencyText, subtitle: "Mac → \(model.displayedConfig?.client ?? "PS5") · 局域网", symbol: "gamecontroller")
                Divider()
                TrafficMetric(title: "Google Ping", value: model.googleLatencyText, subtitle: "经网络出口 → 8.8.8.8 · ICMP", symbol: "globe")
                Divider()
                TrafficMetric(title: "Google HTTPS", value: formatLatency(model.matchedHealth?.googleHTTPSLatency), subtitle: "www.google.com:443 · 请求耗时", symbol: "network")
            }.fixedSize(horizontal: false, vertical: true)
            Text("约每 5 秒检测 · Ping 可能由网络出口代答；HTTPS 含解析、建连和 TLS 耗时。")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private var serverCard: some View {
        CollapsibleCard("PS5 目标服务器", symbol: "server.rack", key: "servers", summary: "\(model.connections.count) 个目标 · 域名优先") {
            HStack(spacing: 12) {
                Text("协议").frame(width: 42, alignment: .leading)
                Text("目标域名").frame(maxWidth: .infinity, alignment: .leading)
                Text("端口").frame(width: 54, alignment: .trailing)
                Text("出口 Ping").frame(width: 82, alignment: .trailing)
                Text("TCP 建连").frame(width: 82, alignment: .trailing)
                Text("连接状态").frame(width: 76, alignment: .trailing)
            }.font(.caption).foregroundStyle(.secondary)
            if model.connections.isEmpty {
                Text(model.ratesFresh ? "等待 PS5 建立新的连接…" : "开始转发后显示 PS5 实际访问的域名和端口。")
                    .font(.callout).foregroundStyle(.secondary).padding(.vertical, 8)
            } else {
                ForEach(model.connections) { row in
                    Divider()
                    HStack(spacing: 12) {
                        Text(row.protocol).frame(width: 42, alignment: .leading)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(row.serverName).lineLimit(1).truncationMode(.middle)
                            Text(row.domain == nil ? "未识别域名" : "\(row.domainSource ?? "域名")\((row.aliases?.count ?? 0) > 1 ? " · 同 IP 另有 \((row.aliases?.count ?? 1)-1) 个域名" : "")")
                                .font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                        }.frame(maxWidth: .infinity, alignment: .leading).help(row.serverDetail)
                        Text(String(row.port)).frame(width: 54, alignment: .trailing)
                        Text(model.serverLatencyText(row.ip)).frame(width: 82, alignment: .trailing)
                        Text(row.protocol == "UDP" ? "—" : (row.dialFailed ? "失败" : formatLatency(row.connectLatency))).frame(width: 82, alignment: .trailing)
                        Text(row.active > 0 ? "活跃 \(row.active)" : "最近连接").frame(width: 76, alignment: .trailing)
                            .foregroundStyle(row.active > 0 ? Color.green : Color.secondary)
                    }.font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                }
            }
            Text("优先显示连接主机名，其次显示 DNS 关联域名；无法识别时保留 IP。悬停可查看原始地址和其他关联域名。")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Text("HTTPS 的完整页面路径不可见；同一 IP 可能关联多个域名。Ping 和 TCP 建连不等同游戏内延迟。最多显示 12 个目标，已关闭目标保留约 60 秒。")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }

    private var macCard: some View {
        CollapsibleCard("配置 Mac", symbol: "wifi", key: "mac", summary: model.selectedLAN?.address ?? "待配置") {
            Text("与 PS5 相同的网络").font(.callout).foregroundStyle(.secondary)
            Picker("网络", selection: $model.interfaceName) {
                if model.inventory.interfaces.isEmpty { Text("未检测到局域网").tag("") }
                ForEach(model.inventory.interfaces) { item in Text("\(item.title) · \(item.address)").tag(item.name) }
            }.labelsHidden().disabled(model.active || model.busy)
            if let lan = model.selectedLAN {
                SettingRow(label: "Mac 地址", value: lan.address, emphasis: true)
                SettingRow(label: "子网掩码", value: lan.mask)
            }
            Divider()
            Text("PS5 当前的 IPv4 地址").font(.callout)
            TextField("例如 192.168.50.100", text: $model.clientIP)
                .textFieldStyle(.roundedBorder).font(.system(.body, design: .monospaced)).disabled(model.active || model.busy)
            Text(model.validation ?? "地址有效。请确认这个地址属于 PS5，而不是路由器。")
                .font(.caption).foregroundStyle(model.validation != nil && !model.clientIP.isEmpty ? Color.orange : Color.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }.frame(maxWidth: .infinity)
    }

    private var ps5Card: some View {
        CollapsibleCard("设置 PS5", symbol: "gamecontroller", key: "ps5", summary: model.displayedConfig?.client ?? "待配置") {
            HStack {
                Text("当前 Wi-Fi → 高级设定").font(.callout).foregroundStyle(.secondary)
                Spacer()
                Button(action: model.copySettings) { Image(systemName: "doc.on.doc") }.help("复制 PS5 设置")
            }
            SettingRow(label: "IP 地址设定", value: "手动")
            SettingRow(label: "IPv4 地址", value: model.displayedConfig?.client.isEmpty == false ? model.displayedConfig!.client : "填写 PS5 地址")
            SettingRow(label: "子网掩码", value: model.displayedConfig?.mask ?? "—")
            SettingRow(label: "默认网关", value: model.displayedConfig?.gateway ?? "—", emphasis: true)
            Divider()
            SettingRow(label: "首选 DNS", value: "1.1.1.1")
            SettingRow(label: "备用 DNS", value: "8.8.8.8")
            SettingRow(label: "MTU", value: "自动")
            SettingRow(label: "代理服务器", value: "不使用", emphasis: true)
            Text("保存后，在 PS5 测试互联网连接并实际打开 YouTube 或游戏。")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }.frame(maxWidth: .infinity)
    }

    private var hintsCard: some View {
        CollapsibleCard("使用提示", symbol: "info.circle", key: "hints") {
            Text("本工具共享 IPv4。若 PS5 同时使用 IPv6，它可能绕过 Mac；要让这些流量也遵循本方案，请在路由器上关闭该网络的 IPv6。两台设备不要使用开启设备隔离的访客 Wi-Fi。")
                .font(.callout).fixedSize(horizontal: false, vertical: true)
        }
    }

    private var diagnosticsCard: some View {
        CollapsibleCard("诊断与日志", symbol: "list.bullet.rectangle", key: "diagnostics") {
            Text("当前公网路由接口：\(model.inventory.routeInterface.isEmpty ? "未知" : model.inventory.routeInterface) · PS5 数据包：\(model.status?.packets ?? 0)")
                .font(.system(.caption, design: .monospaced)).textSelection(.enabled)
            Text(model.status?.logs.joined(separator: "\n") ?? "尚未启动转发。")
                .font(.system(.caption, design: .monospaced)).textSelection(.enabled)
            HStack {
                Button("检测转发权限", action: model.probe).disabled(model.busy || model.validation != nil || model.inventory.vpn == nil)
                Button("刷新检测", action: model.refresh)
                Button("导出诊断", action: model.exportDiagnostics)
            }
        }
    }

    private var helpSheet: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("让 PS5 通过 Mac 连接全球游戏网络").font(.title2.bold())
            Text("1. Mac 和 PS5 连接同一路由器的普通 Wi-Fi。\n\n2. Mac 连接 Shadowrocket；测试期间可选择全局代理。\n\n3. 切换到“设置”，展开“配置 Mac”，填写 PS5 当前 IPv4 地址，在顶部点击“开始转发”。\n\n4. 在“设置”页面展开“设置 PS5”，按参数手动设置 PS5；默认网关是 Mac 地址，代理服务器选“不使用”。\n\n5. 切换到“监控”查看状态、流量、延迟与目标服务器，并在 PS5 打开 YouTube 或游戏实测。节点需支持相应 UDP 流量；本工具不保证降低延迟或改变 PSN NAT 类型。\n\n6. 停止使用时点击顶部“停止转发”，把 PS5 的 IP 和 DNS 改回自动。关闭应用后转发自动停止，本版不改写系统转发、路由或防火墙规则。")
                .lineSpacing(5).fixedSize(horizontal: false, vertical: true)
            Text("点击顶部“监控／设置”切换页面，不会停止转发或重置统计。卡片默认折叠，整条标题栏均可点击，并记住你的选择。转发权限检测与诊断导出位于“设置 → 诊断与日志”。域名来自连接主机名或 PS5 的 DNS 回应；加密路径与加密主机名不可见时不会猜测。")
                .font(.callout).foregroundStyle(.secondary)
            HStack { Spacer(); Button("明白了") { model.showHelp = false }.keyboardShortcut(.defaultAction) }
        }.padding(28).frame(width: 590)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) { NSApplication.shared.activate(ignoringOtherApps: true) }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

@main struct PS5VPNBridgeApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    var body: some Scene {
        WindowGroup("游界桥") { BridgeView() }
            .defaultSize(width: 940, height: 860)
            .commands { CommandGroup(replacing: .newItem) {} }
    }
}
