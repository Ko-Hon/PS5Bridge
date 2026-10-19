import Foundation
import Darwin

@main struct CoreTests {
    static func main() throws {
        var tests = 0
        func expect(_ condition: @autoclosure () -> Bool, _ name: String) {
            guard condition() else { fatalError("FAIL: \(name)") }
            tests += 1; print("PASS: \(name)")
        }
        let lan = LANInterface(name: "en0", title: "Wi-Fi", address: "10.42.0.10", mask: "255.255.255.0")
        let vpn = VPNInterface(name: "utun4", address: "198.18.0.1")
        let inventory = Inventory(interfaces: [lan], vpn: vpn, routeInterface: "utun4")
        func config(_ client: String, mask: String = "255.255.255.0", interface: String = "en0") -> BridgeConfiguration {
            BridgeConfiguration(interface: interface, gateway: lan.address, mask: mask, client: client)
        }
        expect((try? config("10.42.0.50").validate(against: inventory)) != nil, "same-subnet PS5 accepted")
        for invalid in ["10.42.0.10", "10.42.1.50", "10.42.0.0", "10.42.0.255", "127.0.0.1", "8.8.8.8", "10.042.0.50", "1.2.3.4;id", "", "192.168.50.256"] {
            expect((try? config(invalid).validate(against: inventory)) == nil, "reject invalid client: \(invalid)")
        }
        expect((try? config("10.42.0.50", interface: "en0;id").validate(against: inventory)) == nil, "reject interface injection")
        let changed = Inventory(interfaces: [LANInterface(name: "en0", title: "Wi-Fi", address: "10.42.0.11", mask: lan.mask)], vpn: vpn, routeInterface: "utun4")
        expect((try? config("10.42.0.50").validate(against: changed)) == nil, "reject stale Mac address")
        let malformedMask = Inventory(interfaces: [LANInterface(name: "en0", title: "Wi-Fi", address: lan.address, mask: "255.0.255.0")], vpn: vpn, routeInterface: "utun4")
        expect((try? config("10.42.0.50", mask: "255.0.255.0").validate(against: malformedMask)) == nil, "reject non-contiguous subnet mask")
        let data = try JSONEncoder().encode(config("10.42.0.50"))
        let decoded = try JSONDecoder().decode(BridgeConfiguration.self, from: data)
        expect(decoded == config("10.42.0.50"), "configuration round trip")
        expect(ps5Settings(config("10.42.0.50")).contains("代理服务器：不使用"), "gateway instructions do not enable HTTP proxy")
        var dual = config("10.42.0.50")
        dual.additionalClients = ["10.42.0.60"]; dual.ipv6Enabled = true
        expect((try? dual.validate(against: inventory)) != nil, "PS5 and iPhone accepted together")
        let decodedDual = try JSONDecoder().decode(BridgeConfiguration.self, from: JSONEncoder().encode(dual))
        expect(decodedDual == dual, "dual-stack configuration round trip")
        expect(ps5Settings(dual).contains("iPhone") && ps5Settings(dual).contains("IPv6"), "copied settings include phone and IPv6 guidance")
        for invalid in ["10.42.0.50", "10.42.0.10", "10.42.1.60", "10.42.0.255", ""] {
            var bad = dual; bad.additionalClients = [invalid]
            expect((try? bad.validate(against: inventory)) == nil, "reject invalid additional device: \(invalid)")
        }
        let legacy = Data("{\"interface\":\"en0\",\"gateway\":\"10.42.0.10\",\"mask\":\"255.255.255.0\",\"client\":\"10.42.0.50\"}".utf8)
        let legacyConfig = try JSONDecoder().decode(BridgeConfiguration.self, from: legacy)
        expect(!legacyConfig.dualStack && legacyConfig.clients.count == 1, "legacy configurations remain IPv4 single-device")
        let probe = try command("/usr/bin/printf", ["hello"])
        expect(probe.code == 0 && probe.output == "hello", "subprocess output drains without waiting for EOF")
        let began = Date()
        expect((try? command("/usr/bin/yes", ["x"], timeout: 0.08)) == nil, "subprocess timeout handles continuous output")
        expect(Date().timeIntervalSince(began) < 3, "subprocess timeout remains bounded")
        var ledger = TrafficLedger()
        ledger.beginEngine()
        ledger.consume(upload: 100, download: 500, uploadRate: 10, downloadRate: 20, lastClientAt: 100)
        ledger.consume(upload: 100, download: 500, uploadRate: 10, downloadRate: 20, lastClientAt: 100)
        expect(ledger.value.totalBytes == 600, "repeated metrics do not double count")
        ledger.beginEngine()
        ledger.consume(upload: 30, download: 70, uploadRate: 3, downloadRate: 7, lastClientAt: 110)
        expect(ledger.value.uploadBytes == 130 && ledger.value.downloadBytes == 570, "VPN reconnect preserves session traffic totals")
        ledger.pause()
        expect(ledger.value.uploadRate == 0 && ledger.value.downloadRate == 0 && ledger.value.totalBytes == 700, "stop clears speed and retains totals")
        ledger.consume(upload: 20, download: 60, uploadRate: .nan, downloadRate: -1, lastClientAt: 90)
        expect(ledger.value.totalBytes == 700 && ledger.value.uploadRate == 0 && ledger.value.downloadRate == 0, "stale counters and invalid rates cannot corrupt totals")
        expect(saturatedAdd(.max, 1) == .max, "traffic counters cannot overflow")
        expect(formatTraffic(0) == "0 B" && formatTraffic(1024) == "1.00 KB", "traffic units scale at 1024 bytes")
        expect(formatLatency(nil) == "—" && formatLatency(.nan) == "—" && formatLatency(-1) == "—", "missing latency cannot appear as a fast connection")
        expect(formatLatency(0.2) == "<1 ms" && formatLatency(42.25) == "42.2 ms", "latency units preserve sub-millisecond samples")
        expect(recently(95, now: 100, seconds: 10) && !recently(80, now: 100, seconds: 10) && !recently(200, now: 100, seconds: 10), "stale and future heartbeats cannot light a lamp")
        var tracker = VPNHealthTracker()
        var health = ConnectionHealth(config: config("10.42.0.50"), vpn: "utun4", lanReady: true, ps5Reachable: true, ps5Latency: 1, vpnReachable: true, googlePing: true, googleLatency: 1, vpnDetail: "ok", checkedAt: 100)
        tracker.record(health)
        expect(tracker.online(config: health.config, vpn: "utun4", now: 105), "verified Google connection lights VPN")
        health.vpnReachable = false; health.checkedAt = 106; tracker.record(health)
        expect(tracker.online(config: health.config, vpn: "utun4", now: 107), "one transient Google failure triggers recheck")
        health.checkedAt = 112; tracker.record(health)
        expect(!tracker.online(config: health.config, vpn: "utun4", now: 113), "two failed checks turn VPN red")
        health.vpnReachable = true; health.checkedAt = 114; tracker.record(health)
        expect(!tracker.online(config: health.config, vpn: "utun5", now: 115) && !tracker.online(config: health.config, vpn: "utun4", now: 140), "changed tunnel and expired success cannot keep VPN green")
        #if BRIDGE_TESTS
        try FileManager.default.createDirectory(atPath: runtimeDirectory, withIntermediateDirectories: true)
        let status = BridgeStatus(phase: "running", message: "test", helperPID: 999, parentPID: 998, config: config("10.42.0.50"), vpn: "utun4", packets: 0, logs: [], updated: 0)
        let legacyData = try JSONEncoder().encode(status)
        let legacyStatus = try JSONDecoder().decode(BridgeStatus.self, from: legacyData)
        expect(legacyStatus.traffic == nil && legacyStatus.metricsAt == nil && legacyStatus.connections == nil, "2.0 status files remain readable")
        let endpoint = ForwardConnection(id: "UDP/8.8.8.8:53", protocol: "UDP", ip: "8.8.8.8", port: 53, active: 1, connectLatency: nil, dialFailed: false, updated: 100)
        let endpointJSON = try JSONEncoder().encode(endpoint)
        let endpointDecoded = try JSONDecoder().decode(ForwardConnection.self, from: endpointJSON)
        expect(endpointDecoded.port == 53 && endpointDecoded.connectLatency == nil, "UDP endpoint metadata round trip preserves absent handshake")
        expect(endpointDecoded.domain == nil && endpointDecoded.serverName == "8.8.8.8", "2.2 connection data remains readable with IP fallback")
        var named = endpointDecoded
        named.domain = "game.example.test"; named.domainSource = "TLS SNI"
        named.aliases = ["game.example.test", "edge.example.test"]
        expect(named.serverName == "game.example.test" && named.serverDetail.contains("8.8.8.8:53") && named.serverDetail.contains("edge.example.test"), "domain display retains original address and alias evidence")
        let control = runtimeDirectory + "/stop-999"
        try Data().write(to: URL(fileURLWithPath: control)); chmod(control, 0o600)
        try requestRelayStop(status)
        let stopValue = try Data(contentsOf: URL(fileURLWithPath: control))
        expect(stopValue == Data([1]), "stop request needs no administrator process")
        chmod(control, 0o644)
        expect((try? requestRelayStop(status)) == nil, "reject broadly writable/readable control file")
        try FileManager.default.removeItem(atPath: control)
        let target = runtimeDirectory + "/target"
        try Data().write(to: URL(fileURLWithPath: target)); chmod(target, 0o600)
        try FileManager.default.createSymbolicLink(atPath: control, withDestinationPath: target)
        expect((try? requestRelayStop(status)) == nil, "refuse symlink in stop channel")
        #endif
        print("\(tests) core checks passed.")
    }
}
