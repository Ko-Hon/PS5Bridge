<p align="center">
  <img src="Assets/Logo.png" width="160" alt="游界桥图标">
</p>

# 游界桥 · PS5Bridge

**先在 Mac 用 Shadowrocket（小火箭）连接 VPN，再用游界桥转发 PS5 的流量。**

使用顺序：**Mac 连接 Shadowrocket VPN → 开启游界桥转发 → PS5 默认网关填写 Mac IP**。Mac 和 PS5 连接同一路由器的普通 Wi-Fi，无需另开热点。

游界桥负责将 PS5 的流量交给 Mac 已连接的 VPN／隧道出口。你需要自行准备 VPN 客户端和可用节点，使用期间保持 **Shadowrocket 与游界桥同时运行**。

## [⬇ 下载 Mac 运行版 · v2.5](https://github.com/Ko-Hon/PS5Bridge/releases/download/v2.5/Youjieqiao-2.5-macOS-arm64.zip)

**这是已经编译好的 Mac 应用，无需编译，也不需要安装 Go 或 Xcode。** 下载 ZIP → 解压 → 将“游界桥.app”拖入“应用程序” → 打开应用。

适用于 **Apple Silicon Mac（M 系列芯片）**，构建最低目标 macOS 13。首次打开可能需要在“系统设置 → 隐私与安全性”中允许；开启转发时需在 macOS 弹窗中完成管理员验证。

仓库根目录的 [游界桥-Mac运行版.zip](游界桥-Mac运行版.zip) 也是同一个运行包，进入文件页面后点击下载即可。[版本说明及校验文件](https://github.com/Ko-Hon/PS5Bridge/releases/tag/v2.5)

---

**让同一 Wi-Fi 下的 PS5，共享 Mac 上已经连接的 VPN 出口。**

游界桥是一款面向 Apple Silicon Mac 的原生网络转发工具。先在 Mac 上通过 Shadowrocket 建立可用的 VPN／TUN 连接，再开启游界桥并把 PS5 的 IPv4 默认网关设为 Mac，PS5 的 IPv4 TCP/UDP 流量即可经这个出口转发到游戏或视频服务。

当前版本：**2.5 · Build 11**。已在开发者的 Mac 与实体 PS5 上验证通讯；其他网络环境和游戏需自行验证。

[下载最新版本](https://github.com/Ko-Hon/PS5Bridge/releases/latest) · [详细使用说明](docs/使用说明.md) · [工作原理](docs/工作原理.md) · [反馈问题](https://github.com/Ko-Hon/PS5Bridge/issues)

## 它能做什么

- **同网段转发**：Mac 和 PS5 继续使用现有 Wi-Fi，PS5 通过手动网关接入。
- **IPv4 TCP / UDP**：用户态处理指定设备的连接，适合视频、下载和支持相应网络条件的游戏。
- **实时监控**：上传／下载速率、本次上传／下载／总流量，以及 PS5、Mac、网络出口的连接状态灯。
- **通讯检测**：PS5 局域网 Ping、经出口访问 Google 的 Ping 与 HTTPS 耗时。
- **目标服务器**：显示目标域名或 IP、端口、协议、活跃连接数、TCP 建连耗时与目标 Ping。
- **原生界面**：“监控”和“设置”两个页面；整条卡片标题均可展开或折叠，并记住展开状态。
- **出口重连处理**：出口接口变化时暂停并重新建立转发，当前会话累计流量保留。
- **可停止、可恢复设置**：点击停止或退出应用结束转发；设备恢复自动网络设置即可回到原来的上网方式。

## 工作方式

Mac 端先连接 Shadowrocket VPN，再启动游界桥。PS5 流量的实际路径为：

```text
PS5 → 同一局域网的 Mac（游界桥）→ Shadowrocket VPN / utun → 上游节点 → 游戏 / 视频服务器
       PS5 的默认网关填写 Mac IP
```

当前已验证的出口客户端是 **Shadowrocket**。如果使用其他 SSR／代理客户端，需要它在 Mac 上建立兼容的 VPN／TUN（`utun`）出口；仅开启 HTTP／SOCKS 系统代理不能提供本工具需要的隧道接口，其他客户端尚未逐一实测。哪些目标经过代理节点仍由出口客户端的规则决定，首次验证时可选择全局代理模式。

转发引擎通过 BPF 接收指定设备发给 Mac 的 IPv4 帧，交给 gVisor Netstack 在用户态处理，再使用绑定指定 `utun` 接口的普通套接字连接目标。回包通过 BPF 返回设备。

当前实现不启用 macOS 内核 IP 转发，不使用 PF 转发规则，也不改写系统路由。管理员验证用于打开 BPF 等必要操作；处理数据包的引擎打开接口后会降权运行。更多细节见[工作原理](docs/工作原理.md)。

## 下载与运行

需要 **Apple Silicon Mac、macOS 13 或更新版本**，以及已建立可用 `utun` 出口的网络客户端。当前发布包仅包含 arm64 版本；最低系统版本来自构建配置，尚未覆盖各 macOS 版本实机验证。

1. 从 [Releases](https://github.com/Ko-Hon/PS5Bridge/releases/latest) 下载 `Youjieqiao-2.5-macOS-arm64.zip`。
2. 解压，将“游界桥.app”放入“应用程序”文件夹。
3. **先在 Mac 打开 Shadowrocket，配置可用节点并开启 VPN／TUN 连接**，确认 Mac 已能通过这个出口访问目标服务；使用游戏时节点需支持相应 UDP 流量。
4. 打开游界桥，在“设置 → 配置 Mac”中选择与 PS5 相同的局域网接口，填写 PS5 当前 IPv4 地址。
5. 点击顶部“开始转发”，在 **macOS 系统弹窗**中完成管理员验证。
6. 按“设置 → 设置 PS5”显示的参数手动配置 PS5，再打开 YouTube 或游戏，观察流量和连接。

使用期间，Mac 上的 Shadowrocket VPN 和游界桥转发都需要保持开启。只打开游界桥而未连接可用的 VPN／TUN 出口，无法建立这条转发路径。

发布包使用本地临时签名（ad-hoc），尚未经过 Apple Developer ID 签名和公证。macOS 可能拦截首次打开；确认下载来源后，可按系统提示在“系统设置 → 隐私与安全性”中允许打开。运行应用不需要安装 Go 或 Xcode。

## PS5 网络设置

| 项目 | 填写方式 |
| --- | --- |
| IP 地址设定 | 手动；与软件中填写的 PS5 地址一致 |
| 子网掩码 | 与当前局域网一致，按软件显示填写 |
| 默认网关 | **Mac 的局域网 IPv4 地址** |
| DNS | 可用的公共 DNS；界面示例为 `1.1.1.1` / `8.8.8.8`，并非强制 |
| MTU | 自动 |
| 代理服务器 | 不使用 |

建议在路由器上为 Mac 和 PS5 保留地址，避免 DHCP 变化。不能使用启用客户端隔离的访客网络。结束使用时，把 PS5 的 IP 和 DNS 改回自动。

## 使用边界

- **一次一台设备**，手动填写地址；尚无自动发现、地址跟随或多设备管理。
- **只转发 IPv4 TCP / UDP**。不转发设备的普通 ICMP，不提供 IPv6、UPnP 或入站端口映射。局域网健康检测的 Ping 是由 Mac 直接发起的。
- IPv6 可能通过原路由器直连；如需让流量遵循本方案，应使用不提供 IPv6 的对应网络。
- Mac 需要保持唤醒，游界桥与出口客户端需持续运行。当前没有常驻服务、菜单栏后台模式、开机启动或自动更新。
- Mac 的局域网地址或接口变化时会停止转发，需要更新设备网关；出口变化也可能中断已有连接。
- 不保证降低延迟、提高下载速度、开放 PSN NAT 类型，或兼容所有节点与游戏。
- 手机等设备在原理上可作为单一目标，界面仍以 PS5 为主，尚未完成手机实机验证。

## 如何理解监控数值

**流量**按设备与 Mac 间的 IPv4 包长统计，含 IP/TCP/UDP 头，不含以太网与隧道外层开销。检测流量不计入设备累计。停止后保留结果，再次开始建立新的统计会话。

**延迟**分别代表局域网 Ping、出口 Ping、HTTPS 请求耗时或 TCP 建连耗时。它们不能直接当作游戏内 RTT；部分出口会代答 Ping，HTTPS 时间还包含解析、TCP、TLS 和响应过程。

**域名**来自被动观察到的 TLS SNI、HTTP Host、DNS A/CNAME 回应。不解密 TLS，不保存网页正文，也不会猜测完整 HTTPS 网址。加密 DNS、ECH 等情况下可能只能显示 IP；共享 IP 的 DNS 关联也不能保证连接使用了某个域名。

## 从源码构建

需要 Apple Silicon Mac、Xcode Command Line Tools、**Go 1.27.2**；测试还需要 `rg`（ripgrep）。依赖及对应许可证已放入 `Relay/vendor` 和 `ThirdParty`。

```sh
git clone https://github.com/Ko-Hon/PS5Bridge.git
cd PS5Bridge
./build.sh
```

生成文件位于 `dist/游界桥.app`。也可指定 Go 路径和输出目录：

```sh
TASK_GO_BIN=/absolute/path/to/go ./build.sh /absolute/path/to/output
```

运行测试：

```sh
./test.sh
```

测试包含 Swift 配置与状态逻辑、旧转发入口拒绝、Go race 检测与 vet、用户态 TCP/UDP 往返、分片、连接限制和异常数据包处理。模拟及回环测试不能代替实体设备、无线网络和具体游戏的验证。

## 反馈问题

请在 [Issues](https://github.com/Ko-Hon/PS5Bridge/issues) 中说明 macOS 版本、软件版本、出口客户端、操作步骤与实际现象。诊断导出可能包含局域网地址、目标域名/IP 和端口，公开反馈前请删除个人信息。无需提供节点密码、订阅链接或访问令牌。

第三方依赖的许可和 notices 见 [ThirdParty](ThirdParty)。本项目为独立工具，与 Sony、PlayStation、Apple 或 Shadowrocket 无隶属或官方合作关系。
