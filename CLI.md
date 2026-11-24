# Nodus CLI 命令规范

本文登记 `nodus` 在当前 L0 开发工作区可用的命令、部分实现的入口和后续阶段规划。通用设计、命令登记和稳定发布规则见[《命令行与输出契约》](agents/命令行与输出契约.md)。

## 当前命令（L0）

| 命令 | 已实现行为 |
| --- | --- |
| `nodus help`、`nodus -h`、`nodus --help` | 显示当前可用命令和全局选项。`nodus version --help` 查看版本帮助，`nodus config --help` 查看配置帮助。`--json` 返回帮助主题和正文。 |
| `nodus version`、`nodus -V`、`nodus --version` | 返回 CLI 和 Core 版本、Core ABI、构建来源、目标信息及当前阶段能力。TUN、透明网关、Mesh 和服务端均标为不可用。`nodus version` 不接受额外位置参数。 |
| `nodus config check <FILE>` | 离线校验指定类型的配置，校验和输出均成功时退出 `0`。 |
| `nodus config summary <FILE>` | 使用同一离线校验流程，成功后输出与配置类型对应的只读摘要。 |

**部分实现的入口**。L0 的 `nodus run`（别名 `nodus daemon`）要求显式主配置路径和内存预算，核验可选的日志与状态目录，并执行主配置离线校验。前置检查通过后返回 `Unsupported`（退出码 `7`）。常驻进程、控制 Socket 和信号处理属于 L1，`--enable-tun` 对应的系统接管属于 L2。详见[守护进程与基础观测](#31-守护进程与基础观测)。

## 1. 全局约定

### 1.1 二进制与全局参数

```text
nodus [全局选项] <子命令> [子命令选项] [参数]
```

| 选项 | L0 行为 | 默认值或来源 |
| --- | --- | --- |
| `--config <FILE>` | 可在命令前指定。离线 `config check/summary` 也可用位置参数，`run` 也接受命令名后的 `--config`。全局路径与位置参数或 `run` 内的路径冲突时退出 `2`。 | 调用方提供 |
| `--memory-budget <SIZE>` | `run` 必填，离线 `config check/summary` 可选。有效值交给 Core 根预算池。支持字节整数及 `B`、`K/KB/KiB`、`M/MB/MiB`、`G/GB/GiB`，带 K、M、G 的单位按 1024 进位。非法值退出 `2`。 | 调用方提供 |
| `--connection-limit <N>` | 与显式内存预算配合，核对正整数及连接槽位所需内存。L0 尚未对运行中的连接执行数量限制。 | 调用方提供 |
| `--socket <PATH>` | 接受并校验显式路径。L0 尚未连接控制 Socket。 | 路径解析规则为 root 使用 `/run/nodus/nodus.sock`，非 root 使用 `$XDG_RUNTIME_DIR/nodus/nodus.sock`。非 root 未设置该变量或留空时需显式传路径。 |
| `--timeout <DURATION>` | 在命令前接受并校验正整数时长，支持 `ms`、`s`、`m`，无后缀按秒处理。L0 尚未执行 IPC 请求超时。 | `10s` |
| `--json` | 输出机器可读结果。与顶层 `-h`／`--help` 或 `-V`／`--version` 连用时，放在快捷选项之前。 | 关闭 |
| `-q, --quiet` | 简化支持精简输出的命令。与 `--verbose` 互斥。 | 关闭 |
| `-v, --verbose` | 已接受参数并检查冲突。L0 渲染路径尚未使用该选项输出附加信息。 | 关闭 |
| `-h, --help`／`-V, --version` | 显示帮助或版本。 | 无 |

### 1.2 执行模式与阶段标记

- **`[离线]`**：无需守护进程。配置操作调用 Core 的适用接口。
- **`[守护]`**：规划为常驻前台进程，可由 `systemd` 托管，持有活动 Core 实例与控制 Socket。
- **`[IPC]`**：规划为通过受保护的 Unix Socket 向运行中的守护进程发送版本化请求。权限以[《守护进程与本地控制规范》](agents/守护进程与本地控制规范.md)为准。
- **`[特权]`**：涉及 Linux TUN、nftables、路由或系统 DNS 等操作。具体授权按对应能力设计。
- **`L0`／`L1`／`L2`／`L3`**：项目的交付阶段，开发路线记录在本地 `TODO.md`。当前可用范围见文首。

解析器已识别但能力尚未启用的入口，在适用的前置检查通过后返回结构化 `Unsupported`（退出码 `7`，Core 错误码 `100023`）。预算、路径及权限检查按该入口和已传参数执行，失败时返回实际错误。解析器无法识别的命令返回用法错误（退出码 `2`）。

### 1.3 密钥与凭据

禁止在命令行参数中直接传递私钥、PSK、Tailscale Auth Key、管理 API Token 或 CA 私钥。L0 对参数终止符前已登记的明文凭据选项拒绝调用，退出 `5`。密钥文件、私有目录和受控环境变量的规范见[《守护进程与本地控制规范》](agents/守护进程与本地控制规范.md#四密钥与受控诊断)。L0 在适用的前置路径核验密钥文件和私有目录，尚未启用的操作不会向守护进程交付密钥。

### 1.4 退出码契约

退出码按失败阶段及结构化错误映射。配置类命令的具体分支见[配置管理](#32-配置管理nodus-config)。

| 退出码 | 含义 |
| --- | --- |
| `0` | 达到该命令的成功条件 |
| `1` | Core 业务或通用操作错误 |
| `2` | 参数或用法错误，例如无效的预算参数 |
| `3` | 配置校验失败，位置和字段信息在 Core 提供时返回 |
| `4` | 守护进程未运行或本地 IPC 不可达，供在线操作使用 |
| `5` | 权限拒绝，例如密钥文件权限过宽 |
| `6` | 超时或操作已取消 |
| `7` | 当前阶段、平台或协议不支持操作 |
| `8` | 操作可能已提交但确认丢失，供在线操作使用 |

### 1.5 JSON 输出契约

机器模式下，CLI 将单次结果写为 stdout 上的一行 UTF-8 JSON，CLI 的结果和错误渲染保持 stderr 为空。预扫描在参数终止符 `--` 前识别独立的 `--json` 选项，以便参数解析失败时也返回 JSON。

离线命令成功示例：

```json
{"ok":true,"schema_version":1,"revision":null,"data":{"topic":"nodus","help":"用法及可用命令"}}
```

参数错误示例：

```json
{"ok":false,"schema_version":1,"error":{"code":null,"name":"UsageError","message":"缺少子命令","phase":"cli-parse","origin":"cli","exit_code":2}}
```

成功对象包含 `ok`、`schema_version`、`revision` 和 `data`，其中 `data` 的结构随命令而定。离线命令的 `revision` 为 `null`。失败对象包含 `ok`、`schema_version` 和 `error`，其中 `error` 始终包含示例中的六个字段。无 Core 错误码时 `code` 为 `null`。存在相应信息时输出 `params`、`issues` 和 `recovery_hint`，仅在诊断被截断时输出 `issues_truncated: true`。由 Core 提供的问题位置可包含 `field`、`line`、`column` 和 `utf16_offset`。自动化应依据机器字段及退出码判断结果。

---

## 2. 命令规划总览

此处为包含 L0 入口的完整规划树。当前版本可完成的操作以文首登记和实际 `--help` 为准。

```text
nodus
├── help                      # 查看当前可用命令 [离线][L0 已实现]
├── run                       # [L0 前置校验已实现] 常驻守护进程 [L1 规划]
├── stop                      # 优雅停止守护进程并等待真实清理 [IPC][L1]
├── status                    # 查看运行状态、流量与预算占用 [IPC][L1]
├── version                   # 查看版本与平台能力矩阵 [离线][L0 已实现]
├── config                    # check / summary [L0 已实现]；apply / reload / current [L1 规划]
├── proxy                     # status / start / stop (SOCKS5 & HTTP 入站) [L1]
├── tun                       # status / up / down / verify (Linux TUN) [L2]
├── route                     # mode / test / stats [L1]
├── node                      # list / select / test / capabilities [L1]
├── conn                      # list / show / close [L1]
├── dns                       # status / query / history / cache / smart-cache [L1/L3]
├── gateway                   # status / up / down / devices / allow / block / unblock / dhcp [L3]
├── mesh                      # up / down / status / peers / ping / routes / admin [L1]
├── device                    # list / capabilities / exec / op / share (G10–G16) [L3]
├── mitm                      # status / ca / capture / rewrite [L3]
├── server                    # run / status (nodus-wireguard-reality 服务端) [L3]
├── logs                      # status / tail / export [L1]
└── diag                      # export [L1]
```

---

## 3. 子命令详细定义

本节中标为 L1、L2 或 L3 的操作属于规划。L0 部分以对应实现说明为准。

### 3.1 守护进程与基础观测

#### `nodus run`（L0 前置校验、L1 守护规划）

L0 接受 `run` 与别名 `daemon`，完成参数、Core 根预算、可选私有目录与主配置校验。非法参数或预算值退出 `2`，目录权限拒绝退出 `5`。Core 预算提交和主配置校验的错误分别按对应阶段映射。前置校验通过后退出 `7`，未创建常驻进程或控制 Socket。

L1 规划启动常驻宿主进程，持有唯一活动 Core 实例并监听本地控制 Socket。

```text
nodus run --config <FILE> --memory-budget <SIZE> [选项]
```

- `--config <FILE>`：主 YAML 配置文件绝对或相对路径（必填）。
- `--memory-budget <SIZE>` 为显式交付给 Core 的根内存预算，必填。如 `64MiB`、`256MiB`。
- `--connection-limit <N>` 为可选连接上限。L0 校验数量及槽位预算。
- `--log-dir <DIR>`：日志与诊断输出目录（遵循私有目录权限检查）。
- `--state-dir <DIR>`：宿主运行态目录（智能缓存快照等）。
- L0 接受 `--enable-tun` 标记。Linux TUN 接管为 L2 规划，需要相应权限。
- L1 信号处理规划为 `SIGINT`／`SIGTERM` 触发优雅退出并等待资源释放，`SIGHUP` 提交与 `nodus config reload` 等价的重载意图。系统网络设置的还原随相应接管能力实现。

#### `nodus stop` `[IPC][L1]`

向运行中的守护进程发出优雅停止指令，并等待其完成真实资源释放与系统网络还原后返回。

```text
nodus stop [--timeout <DURATION>]
```

#### `nodus status` `[IPC][L1]`

输出当前活动实例 ID、运行时长、配置修订代次、路由模式、活动连接数、实时上下行速率与累计流量、真实内存预算占用，以及各子系统（proxy / tun / gateway / mesh / mitm）状态。

#### `nodus version` `[离线][L0 已实现]`

输出版本和当前支持状态，字段以文首登记及 `nodus version --json` 为准。

---

### 3.2 配置管理（`nodus config`）

| 命令 | 模式／阶段 | 说明 |
| --- | --- | --- |
| `nodus config check <FILE> [--kind <main\|gateway\|mesh\|server>]` | `[离线][L0 已实现]` | 使用对应类型的离线校验入口，返回实际结果 |
| `nodus config summary <FILE> [--kind <main\|gateway\|mesh\|server>]` | `[离线][L0 已实现]` | 通过同一校验后返回该类型的只读摘要 |
| `nodus config apply <FILE> [--expected-revision <N>]` | `[IPC][L1]` | 原子发布新配置；若修订不匹配或校验失败，保留当前运行快照且不断开旧连接 |
| `nodus config reload` | `[IPC][L1]` | 重读当前活动配置路径并原子发布 |
| `nodus config current` | `[IPC][L1]` | 查看当前生效配置路径、修订代次、生效时间与摘要 |

离线命令可用 `nodus --config <FILE> config check` 或 `nodus --config <FILE> config summary` 代替位置参数。两种方式同时提供时须指向同一规范化路径。两条命令均可附加 `--memory-budget <SIZE>`。

| `--kind` | L0 输入与机器摘要 |
| --- | --- |
| `main`（默认） | Core 主配置 YAML。JSON 成功结果的 `data.main_summary` 包含路由模式、监听端口、节点和规则数量等。 |
| `gateway`／`server` | 使用 Core 网关定义的 JSON 入口。摘要放在 `data.gateway_summary`。 |
| `mesh` | 解析 Tailscale 类型的 JSON 配置并校验。摘要放在 `data.mesh_network_kind`。 |

参数或预算值非法时退出 `2`。将有效预算提交到 Core 失败时，按原始 Core 错误映射，并标记阶段 `budget-apply`。主配置校验返回错误集合时，首项为文件权限拒绝则退出 `5`，其余情况退出 `3`，包括作为主配置问题返回的预算错误。其他配置类型的文件读取或 Core 校验失败沿各自的错误映射。主配置问题保留原始 Core 错误码，字段位置与截断状态见第 1.5 节。

---

### 3.3 代理入站（`nodus proxy`）

| 命令 | 模式／阶段 | 说明 |
| --- | --- | --- |
| `nodus proxy status` | `[IPC][L1]` | 查看 SOCKS5 / HTTP 入站监听地址、状态与当前会话数 |
| `nodus proxy start [--socks <ADDR>] [--http <ADDR>] [--allow-lan]` | `[IPC][L1]` | 启用本地或 LAN 共享入站监听（默认仅监听 `127.0.0.1`） |
| `nodus proxy stop [--socks \| --http \| --all]` | `[IPC][L1]` | 停止指定或全部代理入站监听，不影响本机 TUN 与 Mesh |

---

### 3.4 Linux 系统 TUN（`nodus tun`）

| 命令 | 模式／阶段 | 说明 |
| --- | --- | --- |
| `nodus tun status` | `[IPC][L2]` | 查看 TUN 接口名、IPv4/IPv6 地址、MTU、物理出口、路由／nftables 代次 |
| `nodus tun up [--mtu <N>] [--dual-stack \| --ipv4-only] [--no-dns]` | `[IPC][特权][L2]` | 启动 `/dev/net/tun` 并事务化应用路由、防回环标记、nftables 与系统 DNS |
| `nodus tun down` | `[IPC][特权][L2]` | 停止 TUN 并按事务记录确定性还原路由、nftables 与系统 DNS |
| `nodus tun verify` | `[IPC][特权][L2]` | 只读核验内核实际接口、策略路由与 nftables 规则是否与已提交代次一致 |

---

### 3.5 路由与规则（`nodus route`）

| 命令 | 模式／阶段 | 说明 |
| --- | --- | --- |
| `nodus route mode [rule\|global\|direct]` | `[IPC][L1]` | 无参数查询当前模式；带参数原子切换路由模式并返回新代次 |
| `nodus route test <TARGET> [--port <N>] [--protocol <tcp\|udp>] [--src-ip <IP>] [--config <FILE>]` | `[离线/IPC][L1]` | 判定目标命中的规则、规则集、原文行号与最终策略（带 `--config` 时离线评测，否则按活动快照评测） |
| `nodus route stats` | `[IPC][L1]` | 返回当前代次有效规则数、规则集条目数与真实命中统计 |

---

### 3.6 节点与测速（`nodus node`）

| 命令 | 模式／阶段 | 说明 |
| --- | --- | --- |
| `nodus node list [--group <NAME>]` | `[IPC][L1]` | 列出代理节点／策略组及当前选中项 |
| `nodus node select <GROUP> <NODE>` | `[IPC][L1]` | 切换指定策略组的当前出站节点 |
| `nodus node test [NODE...] [--group <NAME>] [--mode <tcp\|handshake\|probe>] [--url <URL>] [--timeout <DURATION>]` | `[IPC][L1]` | 执行测速并明确区分 `tcp`（仅建连）、`handshake`（协议握手）与 `probe`（真实代理探针）阶段及结构化失败 |
| `nodus node capabilities [NODE] [--config <FILE>]` | `[离线/IPC][L1]` | 只读查询节点协议、传输层、TLS/REALITY、UDP/XUDP 真实支持能力 |

---

### 3.7 活动连接（`nodus conn`）

| 命令 | 模式／阶段 | 说明 |
| --- | --- | --- |
| `nodus conn list [--limit <N>] [--offset <N>] [--src-ip <IP>] [--node <NAME>]` | `[IPC][L1]` | 分页查看活动连接（ID、来源、目标、命中规则、出站节点、上下行字节、时长） |
| `nodus conn show <ID>` | `[IPC][L1]` | 查看单条连接的完整元数据与阶段信息 |
| `nodus conn close (<ID> \| --src-ip <IP> \| --node <NAME> \| --all)` | `[IPC][L1]` | 主动关闭指定或匹配连接并等待真实释放 |

---

### 3.8 DNS 与智能缓存（`nodus dns`）

| 命令 | 模式／阶段 | 说明 |
| --- | --- | --- |
| `nodus dns status` | `[IPC][L1]` | 查看上游列表、Fake-IP、DNSSEC、缓存条目数与统计 |
| `nodus dns query <DOMAIN> [--type <A\|AAAA\|HTTPS\|TXT>] [--no-cache]` | `[IPC][L1]` | 经 Core DNS 发起受控查询，返回应答、TTL、DNSSEC 验证态、上游来源与是否回退 |
| `nodus dns history [--limit <N>] [--offset <N>]` | `[IPC][L1]` | 分页查看近期 DNS 查询记录（与缓存列表严格分离） |
| `nodus dns cache list [--domain <FILTER>] [--limit <N>] [--offset <N>]` | `[IPC][L1]` | 分页查看当前 DNS 缓存条目与剩余 TTL |
| `nodus dns cache clear [--domain <DOMAIN>]` | `[IPC][L1]` | 清空指定域名或全部 DNS 缓存 |
| `nodus dns smart-cache export <FILE>` | `[IPC][L3]` | 导出智能缓存私有快照至指定文件 |
| `nodus dns smart-cache restore <FILE>` | `[IPC][L3]` | 从快照文件恢复智能缓存（按契约先恢复禁用项再提交） |

---

### 3.9 Linux 透明网关（`nodus gateway`）

| 命令 | 模式／阶段 | 说明 |
| --- | --- | --- |
| `nodus gateway status` | `[IPC][L3]` | 查看透明网关运行状态、接入网卡、来源范围、合计流量与事务代次 |
| `nodus gateway up --config <FILE>` | `[IPC][特权][L3]` | 独立启动透明网关，不中断本机 TUN 及其既有流 |
| `nodus gateway down` | `[IPC][特权][L3]` | 独立停止透明网关并仅还原网关所拥有的系统设置 |
| `nodus gateway devices` | `[IPC][L3]` | 按来源设备列出 IP、MAC/设备名（仅来自 DHCP 或 ARP/NDP）、最后活动时间、连接数与上下行流量 |
| `nodus gateway allow <IP>` | `[IPC][L3]` | 将设备加入白名单 |
| `nodus gateway block <IP>` | `[IPC][L3]` | 拉黑／禁用设备：阻止新流并立即断开该设备的既有转发连接 |
| `nodus gateway unblock <IP>` | `[IPC][L3]` | 解除设备拉黑并恢复接入 |
| `nodus gateway dhcp probe` | `[IPC][特权][L3]` | 探测局域网内现有 DHCP 服务器并如实报告（不修改路由器） |
| `nodus gateway dhcp leases` | `[IPC][L3]` | 查询当前主网关 DHCP 租约（主机名、MAC、IP、到期时间与已分配数） |

---

### 3.10 Mesh 与 Tailscale／Headscale（`nodus mesh`）

> 支持多网络实例并存，所有命令均通过 `--network <ID>` 隔离网络归属与身份，禁止跨网络隐式桥接。

| 命令 | 模式／阶段 | 说明 |
| --- | --- | --- |
| `nodus mesh up --network <ID> --backend <nodus\|tailscale\|headscale> [选项]` | `[IPC][L1]` | 加入指定网络；选项：`--control-url <URL>`、`--config <FILE>`、`--auth-key-file <FILE>`、`--key-dir <DIR>`、`--hostname <NAME>`、`--exit-node <PEER>`、`--advertise-routes <CIDR,...>` |
| `nodus mesh down [--network <ID>]` | `[IPC][L1]` | 退出指定（或全部）Mesh 网络并撤销旧代次连接 |
| `nodus mesh status [--network <ID>]` | `[IPC][L1]` | 查看登录生命周期状态、本机节点身份、虚拟 IPv4/IPv6、控制面与在线节点数 |
| `nodus mesh peers [--network <ID>]` | `[IPC][L1]` | 列出对端节点、当前路径（直连／DERP 及区域）、远端端点、RTT、最近经验证握手时间与上下行字节 |
| `nodus mesh ping <PEER> [--network <ID>] [--count <N>] [--via <auto\|direct\|derp>]` | `[IPC][L1]` | 经 DISCO／DERP／WireGuard 发送路径探针并输出真实往返时延 |
| `nodus mesh routes [--network <ID>] [--set-exit-node <PEER\|none>]` | `[IPC][L1]` | 查看子网路由与 Exit Node 状态，或显式切换／取消 Exit Node（绝不自动改变默认出口） |
| `nodus mesh admin nodes --network <ID> --token-file <FILE>` | `[IPC][L1]` | 经独立管理凭据查询 Tailscale／Headscale 网络节点列表 |
| `nodus mesh admin approve <NODE_ID> --network <ID> --token-file <FILE>` | `[IPC][L1]` | 审批待准入节点 |
| `nodus mesh admin remove <NODE_ID> --network <ID> --token-file <FILE>` | `[IPC][L1]` | 移除节点并撤销其访问权限 |
| `nodus mesh admin routes <NODE_ID> --enable <CIDR,...> --network <ID> --token-file <FILE>` | `[IPC][L1]` | 审批节点的子网路由／出口宣告 |
| `nodus mesh admin acl get --network <ID> --token-file <FILE>` | `[IPC][L1]` | 读取远端网络策略（ACL / HuJSON） |
| `nodus mesh admin acl set <FILE> --network <ID> --token-file <FILE>` | `[IPC][L1]` | 提交远端网络策略并返回真实服务端校验结果 |

---

### 3.11 统一设备控制（`nodus device`，G10–G16）

> 不提供通用任意命令／任意脚本执行；仅支持经逐操作授权校验的类型化操作。对仅运行官方 Tailscale 客户端的节点，如实返回“网络可达但操作不支持”。

| 命令 | 模式／阶段 | 说明 |
| --- | --- | --- |
| `nodus device list [--network <ID>]` | `[IPC][L3]` | 列出已注册的可控节点与经网关发布的 LAN 资源 |
| `nodus device capabilities <NODE> [--network <ID>] [--resource <ID>]` | `[IPC][L3]` | 查询目标节点或 LAN 资源真实支持的能力清单 |
| `nodus device exec <NODE> <OP> --network <ID> [--resource <ID>] [--params-file <JSON>] [--idempotency-key <KEY>] [--timeout <DURATION>]` | `[IPC][L3]` | 提交类型化设备操作，严格区分已发送／执行中／成功／失败／结果未知（有副作用操作断线不自动重放） |
| `nodus device op status <REQ_ID>` | `[IPC][L3]` | 查询在途或历史操作的真实执行状态与回执 |
| `nodus device op cancel <REQ_ID>` | `[IPC][L3]` | 尝试取消在途操作并如实返回是否可撤回 |
| `nodus device share list` | `[IPC][L3]` | 查看本机作为网关发布的受限 LAN 资源清单 |
| `nodus device share add --id <RES_ID> --target <HOST:PORT> --protocol <tcp\|udp> [--allow-peer <PEER,...>]` | `[IPC][L3]` | 受限发布单个 LAN 设备／服务（不开放整个子网） |
| `nodus device share revoke <RES_ID>` | `[IPC][L3]` | 撤销资源发布并断开对应远程转发会话 |

---

### 3.12 MitM、去广告与显式抓包（`nodus mitm`）

| 命令 | 模式／阶段 | 说明 |
| --- | --- | --- |
| `nodus mitm status` | `[IPC][L3]` | 查看 MitM 启用状态、生效域名范围、HTTP/2 与 QUIC 回退策略及 CA 绑定状态 |
| `nodus mitm ca load --cert-file <FILE> --key-file <FILE>` | `[IPC][L3]` | 向活动会话安全交付本地 CA 签发身份（检查 `0600` 权限，私钥不落日志） |
| `nodus mitm capture start [--domain <FILTER>] [--limit <N>]` | `[IPC][L3]` | 启动受控显式请求捕获（遵循独立预算上限） |
| `nodus mitm capture stop` | `[IPC][L3]` | 停止捕获并清理未提交缓冲，不中断既有连接 |
| `nodus mitm capture status` | `[IPC][L3]` | 查看捕获状态、已采条目数与缓冲占用 |
| `nodus mitm rewrite stats` | `[IPC][L3]` | 查看各原生复写插件／规则的命中、跳过、失败统计 |
| `nodus mitm rewrite explain <REQ_ID>` | `[IPC][L3]` | 查看单条请求的脱敏复写诊断（配置修订、命中插件、实际动作与结果） |

---

### 3.13 服务端模式（`nodus server`）

| 命令 | 模式／阶段 | 说明 |
| --- | --- | --- |
| `nodus server run --config <FILE> --key-file <FILE> --memory-budget <SIZE>` | `[守护][L3]` | 启动 `nodus-wireguard-reality` 服务端（TCP 443 + REALITY 回落 + 服务端 DoH/DoT/出站 + 后续 QUIC 端口协商） |
| `nodus server status` | `[IPC][L3]` | 查看服务端监听端口、当前 QUIC 端口租期／协商轮次、已认证客户端数与出站状态 |

---

### 3.14 日志与诊断（`nodus logs` / `nodus diag`）

| 命令 | 模式／阶段 | 说明 |
| --- | --- | --- |
| `nodus logs status` | `[IPC][L1]` | 查看访问日志与诊断日志目录、轮转文件数、写入状态与错误计数 |
| `nodus logs tail [--channel <access\|runtime\|all>] [--level <info\|warn\|error>] [--lines <N>] [--follow]` | `[IPC][L1]` | 实时查看或回看运行日志 |
| `nodus logs export <OUT_DIR> [--key-file <FILE>] [--since <TIME>]` | `[离线/IPC][L1]` | 导出或使用宿主密钥解密读取 `NODLOG2` 加密日志容器 |
| `nodus diag export <OUT_FILE>` | `[IPC][L1]` | 导出脱敏结构化诊断包（配置代次、错误统计、预算水位、子系统状态，严禁包含私钥与凭据） |

---

## 4. 使用示例

### 4.1 当前可用（L0）

```bash
nodus --help
nodus version --json
nodus config check /etc/nodus/router.yaml
nodus config summary /etc/nodus/router.yaml --json
```

### 4.2 后续阶段规划

以下示例对应后续阶段。当前 `run` 仅执行前置校验，其他尚未启用的入口见第 1.2 节。

```bash
# L1 守护进程
nodus run --config /etc/nodus/router.yaml --memory-budget 256MiB --log-dir /var/log/nodus

# L1 原子热更新配置与路由测试
nodus config apply /etc/nodus/router.yaml
nodus route test api.example.com --port 443 --protocol tcp --json

# L1 加入自建 Headscale 网络并查看对端路径（免 root 用户态）
nodus mesh up \
  --network lab \
  --backend headscale \
  --control-url https://hs.example.com \
  --auth-key-file /etc/nodus/keys/hs.authkey \
  --key-dir /etc/nodus/keys/lab
nodus mesh peers --network lab
nodus mesh ping peer-a --network lab

# L2 开启系统 TUN 接管并核验（需 CAP_NET_ADMIN）
nodus tun up --dual-stack
nodus tun verify
nodus tun down

# L3 透明网关设备查询与访问控制
nodus gateway up --config /etc/nodus/gateway.yaml
nodus gateway devices
nodus gateway block 192.168.50.23
```
