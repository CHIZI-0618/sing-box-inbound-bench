# sing-box 透明入站横向基准测试方案

> 状态：完整可执行测试工具；已有单台 Android 真机样本，仍待不同 Linux/Android 设备
> 交叉验证。本文档不包含任何未经本仓库协议采集的性能结论。

执行入口：[快速开始](docs/quick-start.md)；Android 部署与恢复：
[Android execution and recovery](docs/android.md)；首份真机样本：
[2026-09-18 正式真机横评报告](docs/formal-real-device-report-20260918.md)。

当前原型已经实现：

- 版本化配置、manifest 和逐 repetition 结果格式；
- 原生 TCP echo、真正单向连续流的 bulk upload/download、短连接 client/server；TCP short
  同时记录总耗时、建连耗时和建连后的应用回显耗时；
- TCP `idle` 会在连接仍保持打开时同步采样 worker 与 sing-box，用于
  1/250/500/750/1000 连接的内存、FD 与 socket 曲线；
- 原生 UDP echo 与按全局速率调度的开放环固定 offered-load PPS client/server；
- `raw`、`direct`、`redirect`、`tproxy`、`tun`、`tun-auto-redirect`、
  `ebpf-tc`、`ebpf-cgroup` 全部八个 subject；
- sing-box 配置生成、配置检查、子进程管理和 sing-box API eBPF 运行时诊断；
- 客户端与 sing-box 的 CPU、I/O、RSS/PSS/USS/HWM/swap、fault、context switch、
  thread/FD/socket 分账；
- 整机及逐核 CPU、NET_RX/NET_TX softirq、fault、migration、conntrack、指定接口
  bytes/packets/drop/error，以及温度和 CPU 频率前后快照；Linux/Android 还记录测量窗口内
  TCP 重传、SYN 重传、listen overflow/drop 等主机级计数器增量；
- 任一步失败后仍执行 Stop、Cleanup、VerifyRestore 的事务生命周期测试；
- 捕获 SIGINT/SIGTERM 后进入有界清理，并为每个阶段记录起止时间和错误；
- 在删除临时状态前保存脱敏配置、内核探测、stdout、stderr 及 SHA-256；
- controller 只负责生命周期和采样，实际负载由握手后启动的独立 worker 进程产生；
- server 回传其观察到的 peer tuple，用于区分 raw 与经 sing-box 新建 outbound 的路径；
- redirect/TProxy 使用 run ID 专属 chain 和精确 policy rule/route，逐条登记逆操作，
  从不 flush 或替换宿主已有 netfilter 状态；
- TUN 等待真实接口出现，并以接口 RX/TX 增量证明数据路径；auto_redirect 还会证明
  sing-tun 实际选择的 nftables 或 iptables backend 存在；
- Android ADB root 部署、矩阵执行、结果回收、生产服务可选 stop/start，以及运行前后
  rule/route/netfilter/link 状态审计；远端只清理 `/data/local/tmp/sing-box` 下的自有目录。
- `matrix` 按固定 seed 在每个 repetition block 内随机化 subject，支持逐 job 断点续跑，
  并可在每个 block 前后自动执行 raw control；
- `summarize` 仅聚合非 warmup 且 valid 的 repetition，输出 `summary.json`、
  `summary.md` 和超过 5% 的 raw 漂移告警。

eBPF 两个 subject 已完成配置、只加载不挂载的内核能力探测、运行时 attachment 证明和
生命周期框架，并在一台 Android 16 / GKI 6.6 真机上完成 local TC 与 local cgroup 执行链、
失败恢复和生产服务恢复验证；这不代表其他厂商内核、shared/hybrid、IPv6 或 USB 拓扑已经
覆盖。worker 会在创建任何 workload socket 前加入专用 cgroup、切换目标 UID，并向
controller 回报验证结果。eBPF 测试二进制必须启用 `with_ebpf`；运行时诊断通过内置
sing-box API 的 `ebpf` RPC 获取，不依赖 Clash API 或 `with_clash_api`。所有非 raw subject
使用同一份二进制，并统一启动同一只读 API 服务，避免把 API 服务的内存与待机成本只
计入 eBPF subject；只有 eBPF case 会在正式计时窗口外查询诊断。

工具有意不自动修改 USB gadget，也不在 USB 充电条件下伪造直接能耗结论。通过全部
有效性门槛的真实 LAN/USB 输出可用于发布分项比较；缺少 raw control、路径证明或恢复
验证的输出只能作为诊断样本，不能用于排名。

本机最小闭环示例：

```sh
go build -o inbound-bench ./cmd/inbound-bench
./inbound-bench tcp-server -listen 127.0.0.1:19090
# 在另一个终端运行；raw 会拒绝在发现 sing-box 进程时继续：
./inbound-bench run -config configs/raw-tcp-echo.json
```

服务端也可使用 `udp-server`。配置解析拒绝未知字段，结果目录已经存在时拒绝覆盖；API
token 写入结果和 sing-box 配置证据前会被替换为 `<redacted>`。每个 repetition 都会
重新启动被测 sing-box，并在正式计时前完成独立的完整性预热与路径证明。任何阶段失败
都会留下 invalid repetition；Stop、Cleanup 或 VerifyRestore 失败也会反向使本轮无效。
路径证明最多使用 8 个连接/flow 和 8 次回显，不会提前复制 idle/PPS 等正式容量压力。
TCP short 的单连接传输失败和 TCP idle 的建连失败属于被测可靠性/容量结果：worker 会保留
其余成功连接，在 `failed` 保留失败数，并由汇总输出 `Success %`；帧、校验和或路径证明
损坏仍会令 repetition invalid。`Success %` 的分母包含成功操作、TCP `failed` 和 UDP
`lost`，不会把 PPS 丢包显示成 100% 成功。TCP short 的 `latency_ns` 仍表示用户观察到的
完整操作耗时，`connect_latency_ns` 与 `application_latency_ns` 分别用于区分建连停顿和
连接建立后的转发/服务端响应停顿；三组数据只记录成功操作并保持相同的 worker 顺序。
UDP PPS 的 Ops/s 与 Mbit/s 使用 offered-load 的 active 窗口；超时收尾的 drain 时间单独
保留在 workload timing 中，不会再次作为吞吐惩罚。CPU 利用率仍按完整测量 wall time。

矩阵冒烟示例：

```sh
./inbound-bench matrix -config configs/matrix-raw-smoke.json
# 中断后，将配置中的 resume 改为 true；已存在且能完整解码的结果不会重跑。
./inbound-bench matrix -config configs/matrix-raw-smoke.json
# 也可只重新生成汇总：
./inbound-bench summarize -config configs/matrix-raw-smoke.json
```

恢复执行会比较脱敏后的完整矩阵配置；seed、case、工作负载或 subject 参数发生变化时
会拒绝混入旧结果。每个 job 完成后以原子 rename 更新 `state.json`。

生成完整 LAN/USB 横评矩阵：

```sh
./inbound-bench generate-matrix \
  --preset full \
  --output matrix-lan.json \
  --matrix-id pixel8-usb-20260915 \
  --results /data/local/tmp/sing-box/results \
  --sing-box /data/local/tmp/sing-box/sing-box \
  --target 192.168.254.2:19090 \
  --interface rndis0 \
  --worker-uid 2000 \
  --cooldown-ms 1000 \
  --fail-fast=true \
  --udp-pps 100000 \
  --udp-mtu-pps 10000
```

生成器提供 `smoke`、`core`、`full` 三档预设，分别展开 22、114、168 个已校验 case。
完整矩阵包括八个 subject 的 standby、TCP RTT、1/8 长流上传下载、1/32/128 短连接、
1/250/500/750/1000 idle 曲线，以及支持 UDP 的七个 subject 的 connected/unconnected RTT、
1/64-flow PPS、MTU payload 和 1000-flow churn；redirect 的 UDP 会按能力表直接不生成，
而不是产生伪失败。可用 `--subjects` 与 `--workloads` 做显式子集测试。

`--udp-pps` 是普通 PPS workload 的全局 offered load；`--udp-mtu-pps` 单独控制 1432-byte
MTU payload，省略时才继承前者。两者都应先用 raw pilot 找到链路可持续范围，再分别生成
25%/50%/75% 三套矩阵，不能把某台设备的默认 100 kpps 当成统一负载结论。`full` 默认
1 次额外 warmup repetition 加 5 次正式重复，`core` 为 1+3，`smoke` 为 0+1；这里的 0
不取消每轮必须执行的路径证明预热。每个 block 前后仍执行 raw control。自定义参数只
覆盖对应 preset 默认值，不可将不同预设或时长的结果混合统计。`--requests` 可固定 RTT
与 TCP short 的离散尝试数；它不改变 `udp-churn` 的 1000-flow 定义。

生成器默认在相邻 job 间冷却 1 秒。UDP PPS job 结束后还会用 `raw_control` 的物理目标
执行最多 5 次、每次 8 包的低速 UDP 恢复探测；只有 8/8 返回才继续下一个随机 case。
探测不计入被测结果，但其次数、计数与错误会写入 `state.json`。持续过载后网络未恢复时
矩阵会保留部分结果并停止，避免把队列残留误记成后续入站的失败。`--cooldown-ms` 可按
拓扑调整；它不能替代先用 raw pilot 选取可持续 offered load。生成器还默认写入
`fail_fast: true`，第一个 invalid job 完成清理并保存状态后即停止；诊断性批量收集可显式
使用 `--fail-fast=false`。

Android 主机侧执行：

```sh
CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -o build/inbound-bench-android-arm64 ./cmd/inbound-bench
go build -o inbound-bench ./cmd/inbound-bench
./inbound-bench android-run -config configs/android-run.example.json
```

`android-run` 强制确认 `adb shell id -u` 为 0，把基准二进制、同一份 sing-box 二进制和
重写后的矩阵放入 run ID 专属目录。若配置 `service`，status/stop/start 必须分别写成参数
数组；runner 只在原服务确实运行时停止它，并在任何返回路径以不受原取消信号影响的超时
上下文恢复。前后快照和远端日志始终保存在 `<matrix-id>-android-audit`。网络状态不同会令
整个任务失败并保留两份快照。工具有意不自动切换 USB gadget、移动数据、Wi-Fi、默认路由
或充电状态，这些设备全局动作必须由测试者按第 3 节的拓扑说明准备。

本项目计划对 sing-box 的本机透明接管方案进行可复现的横向测试，并同时提供不经过
sing-box 的裸网络基线和经过一次 sing-box 用户态转发的 `direct` 入站基线。

主要被测方案：

- 裸网络直连；
- `direct` inbound；
- `redirect` inbound；
- `tproxy` inbound；
- TUN；
- TUN + `auto_redirect`；
- eBPF local TC；
- eBPF local cgroup。

本文档既是未来测试工具的实现规范，也是第三方测试者提交结果时必须遵循的实验协议。

## 1. 上游参考与边界

本方案参考以下公开资料：

- [SagerNet/tun-bench](https://github.com/SagerNet/tun-bench)，参考提交
  `201b780e709b7da46da75950dfcbf43741d47e34`；
- [《引入新的 sing-tun 自有 TCP/IP stack》](https://sekai.icu/posts/sing-tun-new-stack-introduction/)，
  2026-09-12。

`tun-bench` 值得复用的实验思想包括：

- 测试前进行 TCP/UDP 转发和 UDP 满 MTU 数据完整性探测；
- 将被测进程与 iperf3/辅助进程放在分离且同等级的 CPU 核心上；
- 同时测量不限速吞吐和固定速率下的单位流量 CPU/能耗；
- 以 0、250、500、750、1000 条连接建立内存曲线，而不是只比较单个 RSS 点；
- 保存原始 iperf3 JSON、环境描述和测量协议，拒绝混合不同协议版本的结果；
- 在失败后验证进程、接口和路由确实被清理。

但是，`tun-bench` 当前只面向 TUN 栈，其拓扑是本机 loopback 服务端加测试 TUN host
route；它不能直接回答不同透明接管机制的性能问题。本项目不会把以下限制继承为正式
横评口径：

- 只测 TUN；
- 只统计被测进程 CPU，不统计内核、softirq 和整机 CPU；
- 只测长流吞吐和空闲连接内存；
- 每个 case 只取一个短样本；
- 在云端虚拟机上生成可用于细微性能排名的结果；
- Linux 使用 MTU 9000 的 loopback/TUN 合成链路代替真实 Ethernet MTU；
- 仅以 RSS 表示包括 eBPF map、conntrack、TUN 队列在内的总内存成本。

截至上述参考提交，`SagerNet/tun-bench` 仓库未声明开源许可证。因此，本项目只参考
其公开测试思想和输出维度，不复制或改写其源代码。若未来需要移植代码，必须先取得
明确的许可证或版权所有者授权。

## 2. 要回答的问题

测试结果至少应能分别回答：

1. 不同方案的 TCP 单长流和多长流吞吐上限是多少？
2. 达到相同吞吐时，sing-box 用户态和整个 DUT 分别消耗多少 CPU？
3. TCP 短连接建立、转发和销毁的每秒完成数及尾延迟是多少？
4. 1000 条空闲 TCP 长连接的增量用户态与内核态内存是多少？
5. UDP 单 flow 的延迟、PPS 和吞吐如何？
6. UDP 多 flow 和 flow churn 下是否出现锁竞争、LRU 淘汰、map 满、丢包或错误？
7. eBPF local TC 与 local cgroup 的成本模型有何不同？
8. TUN + `auto_redirect` 的优势来自接管路径、TUN 栈，还是预匹配绕过？
9. 方案退出或失败后是否留下路由、rule、netfilter、TC/TCX、cgroup link、veth 或
   TUN 状态？

不能用一个“总分”取代这些结果。不同方案可能分别在 TCP 长流、短连接、UDP 热路径
或空闲资源占用上领先。

## 3. 测试拓扑

### 3.1 正式主拓扑：外部有线服务端

```text
benchmark client (DUT)
        |
        | 被测透明入站
        v
sing-box direct outbound
        |
        | Ethernet/Wi-Fi，仅经过一次真实 LAN
        v
wired benchmark server
```

要求：

- 服务端以千兆或更高速率有线接入同一 LAN；
- DUT 可使用 Wi-Fi，但 RSSI 建议优于 -60 dBm；
- 服务端 raw baseline 吞吐必须显著高于所有被测方案，否则只报告固定负载效率；
- 服务端 CPU 在 raw baseline 下不得持续超过单个瓶颈核心的 70%；
- 服务端不得运行会接管测试网段的 VPN、透明代理或主机防火墙转发规则。

### 3.2 可接受拓扑：USB 点对点 Ethernet

Android 与测试电脑可以通过同一数据线建立 NCM 或 RNDIS 点对点网络。优先 NCM，
不兼容时再使用 RNDIS。

推荐方式是只启用 USB Ethernet gadget 并手工配置静态 `/30` 地址，不启动 Android
USB tethering、DHCP、NAT、Windows ICS 或 tethering BPF offload。例如：

```text
Android USB interface: 192.168.254.1/30
server USB interface:  192.168.254.2/30
```

不配置默认网关和 DNS。服务端只监听 `192.168.254.2`。

注意：当前 eBPF local TC 跟随 Android default-interface monitor，不会仅因目标存在
USB connected route 就自动挂到 USB 接口。测试工具必须以可回滚的专用 policy rule
和 route table 让 monitor 选择 USB 接口，并在运行时证明 attachment 确实位于
`ncm*`、`rndis*` 或 `usb*`。该规则不得匹配正常用户流量。

ADB 与 USB Ethernet 共享物理链路。正式计时期间不得持续轮询 `adb shell`、实时拉取
日志或传输文件；DUT 在本地缓存指标，case 结束后再统一读取。

### 3.3 辅助拓扑：本机 loopback/TUN 微基准

可另行实现与 tun-bench 类似的本机合成拓扑，用于分离 TUN stack、copy、GSO 和
multi-queue 的理论上限。这类结果不得与真实 LAN/USB 结果混合排名，也不能代表
eBPF local TC 在真实 NIC 上的报文成本。

## 4. 被测对象及语义

| ID | 方案 | TCP | UDP | 主要接管路径 |
| --- | --- | --- | --- | --- |
| `raw` | 裸直连 | 是 | 是 | client socket 到服务端 |
| `direct` | direct inbound | 是 | 是 | 本地 listener，再由 direct outbound 转发 |
| `redirect` | redirect inbound | 是 | 否 | netfilter NAT REDIRECT |
| `tproxy` | TProxy inbound | 是 | 是 | mark、policy route、TPROXY |
| `tun` | TUN | 是 | 是 | route 到 TUN，用户态 TCP/IP stack |
| `tun-auto-redirect` | TUN + auto_redirect | 是 | 是 | auto_redirect 接管后进入 TUN/sing-box |
| `ebpf-tc` | eBPF local TC | 是 | 是 | TC/TCX、socket assignment、内部 delivery |
| `ebpf-cgroup` | eBPF local cgroup | 是 | 是 | CGroupSockAddr socket 操作 |

`direct` inbound 不是透明代理。它代表“经过一次 sing-box 用户态入站和 direct
outbound”的参考下界，报告中必须与 `raw` 区分。

`redirect` 的 UDP 项必须标记为 `not_applicable`，不能以失败或零吞吐代替。

eBPF local TC 与 cgroup 必须作为两个完整、独立的 subject。运行时应记录：

- TCX 或传统 clsact/filter；
- 实际挂载接口及 framing；
- TCP listener lookup 实际选择，而不是只记录预探测结果；
- cgroup attach path 和 multi-attach 状态；
- cgroup UDP time、cleanup、sk_storage 实际选择；
- process tracking 是否启用；
- 所有 fallback 及 verifier/attach 错误。

## 5. 公平性约束

所有 sing-box subject 必须使用完全相同的二进制文件、Go toolchain、构建标签和 direct
outbound。不得用稳定版测试一个入站、开发版测试另一个入站。

统一配置：

- IPv4 为第一阶段主测试；IPv6 使用独立矩阵；
- 日志关闭；
- 不启用 DNS、FakeIP、sniff、规则集下载和 Clash API；所有非 raw subject 仅启用相同的
  loopback sing-box API 服务，用于消除基线差异，eBPF 查询发生在计时窗口外；
- 路由目标使用字面量 IP；
- direct outbound 固定到被测物理接口；
- 透明方案只接管 benchmark UID、目标 `/32` 和测试端口；
- eBPF `bypass_private_address` 必须为 `false`；
- TUN + auto_redirect 不配置 `bypass` action，确保测试流量实际进入 sing-box；
- `udp_timeout` 统一为 `5m`；
- UDP mapping/filtering 统一为 endpoint-independent；
- 主对比的 UDP NAT 容量统一为 `1024`；默认配置行为另开矩阵，不与容量归一化结果
  混合；
- MTU 主测试为 1500；USB 若实际 MTU 不同，应统一到链路共同支持的相同值；
- 不启用 MPTCP、TLS、QUIC 加密等会掩盖入站开销的额外工作。

Android ADB root 环境在配置中用 `execution.worker_uid` 固定负载 UID。eBPF subject 必须
只配置一个相同的 `include_uid`；worker 先加入专用 cgroup，再切换 UID，最后通知
controller 开始采样和创建 socket。controller 与 sing-box 必须留在该 cgroup 外。

也可以在手工诊断时显式降权运行独立客户端，例如：

```sh
su 2000 -c '/data/local/tmp/inbound-bench client ...'
```

eBPF cgroup 测试使用 run-scoped 专用子 cgroup，只将 benchmark worker 放入其中，避免
为了测试在 Android 根 cgroup 与 netd 竞争 attachment。runner 会先证明该路径不存在，
再自行创建；全部 worker 和 sing-box 退出后只用 `rmdir` 回收该空目录，不采用递归删除，
也不接管测试前已经存在的 cgroup。

为保证不同 subject 的进程身份一致，正式矩阵中的 raw、direct、TC 与 cgroup 配置应使用
相同的 `execution.worker_uid`；省略该字段只适合本机开发冒烟，此时 worker 继承 controller
的有效 UID。

## 6. 负载矩阵

### 6.1 TCP

| 名称 | 参数 | 输出 |
| --- | --- | --- |
| 长流上传 | 1、8 条流，各 20s | Gbit/s、CPU s/GiB、系统 CPU |
| 长流下载 | 1、8 条流，各 20s | Gbit/s、CPU s/GiB、系统 CPU |
| 固定速率 | raw 能力的 25%、50%、75% | CPU %/(Gbit/s)、softirq |
| 小包 RTT | 单连接，64B ping-pong，至少 20000 次 | p50/p95/p99/p99.9 |
| 短连接 | connect + 64B 请求/响应 + 服务端主动关闭 | CPS、失败率、延迟分位数 |
| 短连接并发 | 1、32、128 | CPS、CPU ms/1000 conn、尾延迟 |
| 待机 | 预热证明路径后不创建业务 socket | CPU、context switch、idle transition、wakeup source |
| 空闲连接 | 1、250、500、750、1000 | MiB/100 conn、FD/conn、内核状态 |

短连接由服务端主动关闭，避免 DUT 的临时端口和 TIME_WAIT 成为主要限制。每个响应必须
包含请求 token，防止将错误连接或陈旧数据计为成功。

空闲连接使用 `mode: "idle"` 和 `duration_ms`。建立阶段不计入驻留时间；连接建立完毕后
保持到 duration 结束，worker 在通知 controller 采样后才关闭 socket，因此结果中的
RSS/PSS/USS、FD、socket 和 BPF map 状态确实对应连接仍存活的时刻。0 连接基线由
`mode: "standby"` 表示：仍先用短 TCP echo 预热完成接管路径证明，正式计时阶段不创建
业务 socket。它与 `connections=0` 的 idle 负载语义不同；仓库中的
`configs/raw-tcp-idle.json` 给出 250 连接示例。

### 6.2 UDP

| 名称 | 参数 | 输出 |
| --- | --- | --- |
| 单 flow RTT | connected 与 unconnected，64B echo，至少 20000 次 | p50/p95/p99/p99.9、loss |
| 小包 PPS | connected/unconnected，64B，开放环固定 offered load | delivered PPS、loss、reorder、CPU/Mpps |
| MTU payload | IPv4@MTU1500 为 1432B 数据 + 40B 基准头，即 1472B UDP payload | 完整性、吞吐、loss |
| 多 flow | 1、64、256 个长期 flow | PPS、锁竞争迹象、CPU、内存 |
| flow churn | 每个 source port/socket 仅一组请求响应 | flow/s、失败率、CPU/1000 flow |
| 状态驻留 | 0..1000，步长 250 | 用户态、map、socket、conntrack 增量 |
| 超时回收 | 建立状态后静置到 timeout 以后 | 残留状态、回收 CPU、FD/map 数 |

UDP 数据包携带 magic、case ID、flow ID、sequence、发送单调时间和 payload checksum。
开放环发送器必须预分配 buffer，并在平台支持时使用批量收发，避免负载发生器先成为
瓶颈。

`udp_socket_mode: "connected"` 使用 connected UDP socket，覆盖普通 `connect + read/write`
路径；`"unconnected"` 使用真正的 `ListenPacket + WriteTo/ReadFrom`，覆盖 cgroup
`sendmsg/recvmsg` 与 TC 数据面的差异。二者是不同 workload key，raw/direct 基线不会
互相复用或合并。

`offered_pps` 表示整个 workload 的总发送速率，不是每个 flow 的速率。发送器按绝对
单调时钟统一调度并轮询分配给各 flow，避免 flow 数增加时隐式放大 offered load。

结果中的 `bytes_sent` 与 `bytes_received` 只统计应用有效载荷，不包含 TCP benchmark
frame、UDP benchmark header 以及 TCP/IP/Ethernet 头。真实链路字节数必须使用相同测量
窗口内的接口 counters；二者不可互相替代。

饱和 UDP 只能说明“在当前 loss 下的最大 delivered rate”。正式比较还必须报告满足
目标丢包率（例如 `<0.1%`）的最大可持续 offered load。

## 7. 指标与归一化

### 7.1 应用和进程

- sing-box `utime + stime`；
- benchmark client CPU；
- 服务端 CPU 和单核最大占用；
- PSS、RSS、USS、VmHWM、VmSwap；
- goroutine/线程、FD、TCP/UDP socket；
- `/proc/PID/io` 在测量区间内的增量。

至少报告：

```text
process CPU cores = process_cpu_seconds / wall_seconds
CPU seconds/GiB = process_cpu_seconds / delivered_GiB
CPU ms/1000 operations = process_cpu_seconds * 1e6 / completed_operations
```

### 7.2 系统和内核

- `/proc/stat` 总 CPU；
- `/proc/softirqs` 的 NET_RX、NET_TX；
- `/proc/net/snmp` 与 `/proc/net/netstat` 中选定的 TCP 建连、重传、超时、listen
  overflow/drop 计数器；
- context switch、migration、major/minor fault；
- 接口 bytes、packets、drop、error；
- conntrack count；
- TUN queue 与接口统计；
- netfilter 专用 chain 精确 counters；
- eBPF program/map/link 数、map 容量、占用、错误和 fallback counters；
- CPU idle state 的累计驻留时间与 transition 增量；
- `/sys/kernel/debug/wakeup_sources` 可读时的 event/wakeup/time 增量；不可读取时字段缺省，
  不得把缺失数据解释为零唤醒；
- 可用时记录 BPF program run time，但开启 BPF stats 的 profiling 轮次必须与正式计时
  分开；
- 温度、thermal state、各 CPU policy 当前频率；
- Android 电量/功率只作为辅助数据，USB 充电状态下不得给出精确能效结论。

只看 sing-box PID CPU 会漏掉 eBPF、netfilter、路由、softirq 等内核成本。只看 PSS 会
漏掉 BPF map、conntrack 和 TUN 内核队列。用户态和内核态指标必须并列，不能强行合成
一个看似精确的数字。

TCP 协议计数是整机计数而不是某个 worker 或 sing-box 进程的私有计数，后台应用可能贡献
增量。它们用于判断“秒级尾延迟是否同时伴随 SYN 重传或监听队列溢出”，不能脱离分阶段
延迟、raw control 和运行环境单独归因。`summary.md` 只列出中位数非零的 case，完整的逐轮
计数仍保留在 repetition JSON 的 `resources.system_tcp` 中。

工具会从 sing-box 的 `/proc/PID/fd` 与 `fdinfo` 去重枚举其持有的 BPF map，记录 map ID、
类型、key/value size、容量、flags 以及内核在该平台实际公开的 `memlock`。`memlock=0`
表示内核未公开这个字段，不能解释为 map 没有内存成本；工具不会用
`(key_size+value_size)*max_entries` 冒充包含 preallocation、per-CPU 和内核元数据的真实
占用。map 当前 entry 数和程序 run_time 仍应从 eBPF runtime diagnostics/单独 profiling
轮次解释，不能为了正式计时高频扫描 fdinfo 或开启全局 BPF stats。

每个 eBPF 正式 repetition 在计时窗口前后各执行一次 `sing-box api ebpf`，保存完整 JSON
快照。attachment/state/recovery 必须保持正常；assignment、rewrite、reconcile、recovery、
FakeIP ICMP rewrite 以及 UDP NAT eviction/drop/release 失败计数在窗口内增加时，该轮直接
标记 invalid。诊断查询和 map occupancy 遍历都不进入正式 workload 计时区间，也不增加
周期扫描或待机唤醒。

## 8. 执行协议

1. 保存环境 manifest 和所有相关系统状态快照。
2. 运行 raw TCP/UDP 校准，确认服务端和链路不是瓶颈。
3. 对每个 subject 执行配置检查和无负载启动/退出测试。
4. 运行 TCP/UDP 完整性冒烟，并取得“确实被接管”的路径证据。
5. 每个正式 case 启动全新的 subject 进程。
6. 静置 10s，预热 5s，再计时至少 15–20s。
7. 每个 case 至少 5 个有效重复；第 1 个额外 warm-up repetition 不参与统计。
8. 使用可复现随机种子随机化 subject 顺序，避免温度和 DVFS 系统性偏向某个方案。
9. 每个 block 前后各运行一次 raw control。
10. block 结束后清理并验证；全部结束后恢复原服务并验证联网。

有效性门槛：

- block 前后 raw 吞吐漂移不超过 5%；
- raw RTT 中位数和 p99 没有异常阶跃；
- DUT 未进入 thermal throttling；
- benchmark client 和 server 均未成为 CPU 瓶颈；
- subject 路径证据显示测试流量被接管，且没有私网或规则 bypass；
- 数据完整性错误为零；
- 基础设施、路径证明与生命周期没有错误；TCP short/idle 和 UDP 的传输失败或丢包作为结果完整报告；
- cleanup 后状态与基线一致。

不满足门槛的 repetition 应保留原始数据并标记 invalid，不得静默删除或计入汇总。

## 9. 路径证明

每个 subject 必须定义独立的接管证据：

- `raw`：sing-box 未运行、服务端确认 worker 源地址；允许中间层在连接跟踪冲突时改写源端口；
- `direct`：专用 listener 配置存在，且服务端观察到不同于 worker 的 outbound tuple；
- `redirect`：专用 NAT chain packet/byte counters 增加；
- `tproxy`：专用 mangle chain、mark 和 policy route counters 增加；
- `tun`：测试 TUN RX/TX counters 增加；
- `tun-auto-redirect`：实际 auto_redirect backend 状态存在、TUN counters 增加，且配置
  将目标限制为唯一 host route，不允许 pre-match bypass；
- `ebpf-tc`：正确接口存在 TCX/TC attachment，UID 已验证，且 outbound tuple 发生变化；
- `ebpf-cgroup`：正确 cgroup link 存在，worker 在创建 socket 前已进入目标 cgroup，且
  outbound tuple 发生变化。

路径证明在预热阶段完成。TCP/UDP server 会返回其实际观察到的 peer tuple：raw 必须与
worker 的 local tuple 一致；所有经过 sing-box 的方案必须不同，证明服务端看到的是
sing-box 新建的 outbound socket，而不是 worker socket。该证明只适用于无 NAT 的正式
LAN/USB 点对点拓扑，并与各 subject 的 attachment/counter 证据组合使用。正式计时阶段
不执行高频诊断读取；eBPF 仅在测量边界读取一次 before/after 运行时快照。

UDP PPS 将 socket 建立、发送和尾包接收阶段分别记录为 `setup_duration_ns`、
`active_duration_ns` 和 `drain_duration_ns`，吞吐和 offered rate 不得使用包含 setup 或
drain timeout 的总时长计算。

## 10. 事务式状态管理

测试工具只能创建带有唯一 run ID 的自有资源，并且只删除自己创建的资源：

- netfilter chain；
- route table 与 rule；
- mark；
- TUN/veth；
- cgroup 子目录与 attachment；
- TC filter 或 TCX link；
- 临时配置、PID 和 socket；
- Windows USB 地址和 firewall rule。

每次变更前保存快照。runner 必须处理正常退出、SIGINT、SIGTERM、子进程崩溃和超时；
清理失败时停止后续 case，并输出人工恢复命令。不得清空现有 chain、qdisc、route table
或 cgroup。

Android 测试不得修改生产配置目录。若由外部服务管理生产 sing-box，应只调用其公开的
stop/start 接口，并在 finally 阶段恢复及验证 PID、路由和联网。

## 11. 统计和报告

每个指标报告所有有效 repetition、median、IQR/MAD，以及相对 raw 和相对 direct
inbound 的变化。不要仅报告算术平均值。

吞吐与效率分开排序：

- 不限速结果按 delivered throughput；
- 固定速率结果按 CPU seconds/GiB 或 energy/Gbit；
- RTT/CPS 使用分位数和失败率；
- 内存使用多点线性回归，同时展示每个原始点。

建议表格：

```text
Environment: <device/kernel/build/link>
Workload: TCP short, concurrency 32, 64B request/response

Subject             CPS   total p99   connect p99   app p99   SYN retrans   failures
raw                  ...   ...         ...           ...       ...           ...
direct               ...   ...         ...           ...       ...           ...
redirect             ...   ...         ...           ...       ...           ...
tproxy               ...   ...         ...           ...       ...           ...
tun                   ...   ...         ...           ...       ...           ...
tun-auto-redirect     ...   ...         ...           ...       ...           ...
ebpf-tc               ...   ...         ...           ...       ...           ...
ebpf-cgroup           ...   ...         ...           ...       ...           ...
```

报告必须同时附上限制说明，不得将一个设备、一个内核和一条链路的结果外推为所有
Android/Linux 系统的普遍排名。

## 12. 第三方测试者提交清单

第三方无需提交个人生产配置。需要提交：

- DUT 型号、SoC、RAM、系统版本；
- 完整 `uname -a`；
- sing-box commit、二进制 SHA-256、Go 版本和构建标签；
- sing、sing-tun、sing-ebpf、cilium/ebpf 的精确版本；
- 测试工具 commit 与协议版本；
- 网络拓扑、接口类型、协商速率、MTU；
- Android/Linux eBPF capability report；
- 每个 subject 的实际路径证明；
- 原始机器可读结果；
- 清理前后状态差异；
- 温度、频率和 raw controls；
- 所有失败、drop、loss、fallback 和 verifier/attach 摘要。

应移除公网 IP、SSID、BSSID、设备序列号、认证 token、生产规则和应用列表等隐私数据。
测试工具未来应提供自动脱敏 manifest。

建议结果目录：

```text
results/<run-id>/
  manifest.json
  protocol.json
  raw/
  direct/
  redirect/
  tproxy/
  tun/
  tun-auto-redirect/
  ebpf-tc/
  ebpf-cgroup/
  cleanup/
  summary.md
```

每个 subject 目录包含配置副本、路径证据、每个 repetition 的 JSON、stderr 和校验和。

## 13. 仓库结构

```text
cmd/inbound-bench/          CLI
internal/controller/        matrix、随机化、恢复执行
internal/subject/           subject 生命周期接口
internal/subject/direct/    direct inbound
internal/netfilter/         redirect 与 TProxy 的专属系统资源
internal/netdev/            TUN/接口 counters 与监听状态
internal/subject/singbox/   sing-box 入站配置、进程、eBPF API 与路径证明
internal/workload/tcp/      bulk、RTT、short、idle、standby
internal/workload/udp/      connected/unconnected RTT、PPS、flow churn
internal/metrics/           process、system、BPF、netfilter、thermal
internal/platform/android/  ADB、UID、cgroup、USB
internal/platform/linux/    namespace、route、TC
internal/platform/windows/  服务端与 USB NCM/RNDIS
schema/                     配置及结果 JSON Schema
configs/                    无隐私示例矩阵
docs/                       测试协议、恢复和贡献说明
```

subject 生命周期接口至少包含：

```text
Preflight -> Snapshot -> Setup -> Start -> ProvePath -> Measure -> Stop -> CollectArtifacts -> Cleanup -> VerifyRestore
```

任何阶段失败都必须进入 `Cleanup` 和 `VerifyRestore`。

## 14. 推荐实施顺序

1. 固化 protocol、manifest、result schema 和纯函数统计测试。
2. 实现独立 TCP/UDP client/server，先验证 raw 与 direct。
3. 实现进程、系统、温度和接口计量。
4. 实现 eBPF cgroup 与 TC adapters，以及路径证明。
5. ~~实现 redirect、TProxy、TUN 与 auto_redirect adapters。~~
6. ~~实现 Android ADB runner。~~ USB NCM/RNDIS 点对点拓扑保持显式人工准备，避免工具
   擅自改变设备全局 USB 与联网状态。
7. ~~实现随机化重复、断点续跑、事务回滚和自动脱敏矩阵。~~
8. ~~添加 CI。~~ CI 只负责构建、单元测试、namespace 功能测试和 cleanup 验证，不把
   共享云 runner 的性能结果发布为正式排名。

只有真实设备产物通过本文全部有效性门槛后，才发布对应工作负载的分项结果；仓库本身
不内置或自动更新性能排行榜。

## 15. 自动验证边界

GitHub Actions 在 Ubuntu 上执行单元测试、race、vet、gofmt、JSON 语法检查，以及
Android arm64/Windows amd64 交叉构建。单独的 root network namespace job 会实际安装
run-scoped 规则，验证 TCP REDIRECT、TCP TPROXY 和 UDP TPROXY 的包确实进入目标 listener，
专属 chain counters 增长，并在结束后确认 chain 不存在。测试预先编译为单个二进制再进入
无网络 namespace，避免 namespace 内下载依赖。

这些 CI 结果只证明控制面语义和内核功能链路，不构成性能数据，也不能替代 Android GKI、
厂商内核、OpenWrt 或真实 LAN/USB 的设备测试。第三方结果应通过 issue 模板提交完整目录，
不得只贴汇总表。
