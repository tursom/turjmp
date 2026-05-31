# RDP 公网安全访问方案讨论备忘

## 背景

Turjmp 的产品需求是：用户可以在公网上安全、方便地经过我们的跳板机访问客户内网的 RDP 服务。客户内网的 RDP 服务不应直接暴露给公网，客户端网络和服务端网络应尽可能完全隔离。

本备忘整理当前讨论结论，便于后续继续评审和落地设计。

## 核心需求

- 公网用户可以访问内网 Windows RDP 服务。
- 用户体验尽量接近原生 mstsc，不希望每次连接都先手动申请一次临时 token。
- 客户内网不开放公网入站端口。
- 用户侧与客户内网服务端网络隔离，用户不知道真实内网 IP。
- 跳板机负责身份认证、权限校验、会话生命周期和审计。
- 优先保证长期稳定和产品化可维护性。

## 已讨论方案

### Web RDP: Browser + guacd

路径：

```text
Browser
  -> turjmp Web RDP
  -> guacd / FreeRDP
  -> Windows:3389
```

优点：

- 与当前 turjmp RDP WebSocket/guacd 方案匹配。
- 鉴权、凭据托管、录像能力较容易统一实现。
- 客户端无需安装软件，只要浏览器即可。

限制：

- 不是原生 mstsc 体验。
- 浏览器内远程桌面在键盘快捷键、显示、多屏、外设重定向等方面不一定满足所有用户。

定位：

- 适合作为强审计、强管控、需要录像的访问通道。
- 不应作为原生 mstsc 体验的唯一方案。

### 动态端口或静态端口 TCP Relay

路径：

```text
mstsc
  -> turjmp 临时端口或固定端口
  -> TCP relay
  -> Windows:3389
```

优点：

- 实现简单。
- 可以兼容原生 mstsc。

限制：

- 如果是每次动态端口，需要用户每次从 Web 申请或下载 .rdp 文件，体验不稳定。
- 如果是资产固定端口，端口管理复杂，资产多时不可维护。
- 如果是单静态端口，需要依赖 Web 预授权、来源 IP、短期 reservation 或 RDP 初始字段做路由，可靠性和安全边界有限。
- 纯 TCP relay 不解析 RDP，不能做屏幕录像或协议级审计。
- 如果 relay 直接连接目标内网，则需要跳板机和目标内网打通；如果客户内网不开放入站，还需要额外 connector。

定位：

- 可以作为 PoC 或内部低成本方案。
- 不适合作为长期稳定的公网产品主路径。

### 自研客户端: Client + Gateway + Connector

路径：

```text
mstsc
  -> 用户本机 turjmp client 本地端口
  -> 公网 turjmp gateway
  -> 客户内网 connector
  -> Windows:3389
```

优点：

- 不需要实现 RD Gateway 协议。
- 可以很好地隔离客户端网络和服务端网络。
- 长期身份、设备绑定、MFA、资产列表和一键拉起 mstsc 都可以由客户端承载。
- 后续 SSH、数据库、文件传输也可以复用同一套隧道。

限制：

- 自研客户端并不简单。
- 需要处理安装、升级、浏览器唤起、系统权限、杀软误报、企业终端管控、跨平台、日志采集和故障诊断。
- 面向公网用户时，客户端交付和运维复杂度会很高。

定位：

- 如果产品允许安装客户端，这是可控且能力丰富的方向。
- 但它不是低成本捷径，只是把 RD Gateway 协议复杂度换成客户端工程复杂度。

### RD Gateway Compatible Server

路径：

```text
mstsc
  -> 公网 turjmp RD Gateway compatible server
  -> turjmp relay
  -> 客户内网 connector 主动出站
  -> Windows:3389
```

优点：

- 客户端使用 Windows 原生 mstsc，无需安装 turjmp 客户端。
- 用户可以长期配置固定网关地址，不需要每次申请连接。
- 客户内网只需要 connector 主动出站连接公网 gateway，不暴露入站端口。
- 客户端不知道真实资产 IP，客户端网络和服务端网络隔离。
- 复杂度集中在我们可控的服务端和客户内网 connector 上。
- 符合企业级“公网安全访问内网 RDP”的产品形态。

限制：

- RD Gateway 协议兼容是重实现。
- 第一版应避免同时追求 UDP multitransport、屏幕录像和完整协议解析。
- 原生 mstsc 字节流 relay 第一版只能做连接审计，不能可靠做屏幕录像。

定位：

- 如果要求“不安装客户端 + 原生 mstsc + 内网不暴露入站 + 长期稳定”，这是最符合需求的长期主线。

## 推荐方向

当前推荐主线是：自研 RD Gateway compatible server，并保留客户内网 connector。

目标架构：

```text
mstsc
  -> turjmp RD Gateway compatible server (:443)
  -> turjmp relay / control plane
  -> turjmp connector
  -> Windows RDP 服务 (:3389)
```

关键原则：

- 客户端不直接访问客户内网。
- 客户内网不开放公网入站。
- connector 只主动出站连接 turjmp gateway。
- 每次连接实时鉴权，但对用户透明。
- 第一版只做 TCP RDP over HTTPS relay，不做屏幕录像，不做 UDP multitransport。
- 屏幕录像继续由 Web RDP/guacd 通道承载。

## 分阶段实现计划草案

### Phase 0: 协议可行性 PoC

目标：

- 验证 Windows mstsc 能连接到自研 RD Gateway compatible endpoint。
- 明确 MVP 需要支持的 RD Gateway/RPC over HTTP 握手范围。
- 明确第一版不支持的协议能力，例如 UDP multitransport。

产出：

- 最小可运行协议 PoC。
- 与 mstsc 的兼容性测试记录。
- 协议风险清单。

### Phase 1: Gateway 身份认证

目标：

- `rdg-gateway` 监听公网 `:443`。
- 支持 TLS 证书和网关认证。
- 用户使用长期身份登录，而不是每次申请 token。
- 每次连接实时校验用户、资产、账号和策略权限。

待决策：

- 是否接入 AD/LDAP。
- 是否使用 turjmp 自有账号体系。
- MFA 如何与 mstsc 网关认证流程结合。

### Phase 2: 资产路由

目标：

- 客户端填写逻辑目标名，而不是真实内网 IP。
- 示例：

```text
asset-001.rdp.turjmp
asset-uuid.rdp.turjmp
```

- Gateway 将目标名解析为 `asset_id`。
- 根据 `asset_id` 找到目标 connector、内网地址、端口和账号策略。

### Phase 3: Connector 反向隧道

目标：

- 客户内网部署 `turjmp-connector`。
- connector 主动出站连接公网 gateway/relay。
- gateway 鉴权通过后，向 connector 请求打开到目标 Windows `3389` 的 TCP 流。
- gateway 与 connector 之间使用 mTLS、连接保活、流级 multiplexing。

### Phase 4: 会话生命周期和审计

目标：

- 创建会话记录：用户、资产、账号、来源 IP、connector、开始时间。
- 断开时记录结束时间、断开原因、流量统计。
- 支持并发限制、空闲超时、最大会话时长。

说明：

- 原生 mstsc 第一版只做连接审计。
- 屏幕录像不放在第一版 RD Gateway relay 中实现。

### Phase 5: 兼容性和稳定性增强

目标：

- 支持网关凭据缓存。
- 处理目标凭据与网关凭据分离。
- 完善证书校验、重连、超时、限速和错误提示。
- 评估 UDP/multitransport 支持，用于提升弱网和高延迟环境体验。

### Phase 6: Web RDP 录像通道并行

目标：

- 原生 mstsc 通道提供稳定便捷访问。
- Web RDP/guacd 通道提供强审计和录像能力。
- 产品上明确区分“原生访问”和“审计访问”两种模式。

## 暂定结论

- 不建议把动态端口或资产固定端口作为长期主路径。
- 不应低估自研客户端复杂度，它不是显著更简单的替代方案。
- 如果产品坚持不安装客户端、使用原生 mstsc、内网不暴露入站，那么自研 RD Gateway compatible server 是更合适的长期方向。
- 第一版必须严格收敛范围：只做原生 mstsc 连接、网络隔离、实时鉴权和连接审计。
- 录像、UDP multitransport、完整 RDP 协议解析应后置。

## 后续待讨论问题

- 是否必须完全兼容 Windows mstsc 的 RD Gateway 行为。
- 是否允许第一版只支持 Windows mstsc，不支持 macOS/iOS/Android RDP 客户端。
- 网关认证接入 turjmp 自有账号、LDAP/AD，还是两者都支持。
- MFA 在 RD Gateway 流程中的产品交互方式。
- 资产逻辑名的命名规则和解析方式。
- connector 与 gateway 的传输协议选型：mTLS TCP、WebSocket、HTTP/2、QUIC。
- 是否先集成现成 RD Gateway 做验证，再逐步自研替换。
