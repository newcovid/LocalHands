<div align="center">

# LocalHands

**推理在别处运行，这里提供"双手"。**

一个本地 MCP 服务端：让云端 AI 智能体操作你的真实机器——读写文件、执行命令、截取屏幕、
双向搬运二进制文件——通过隧道接入，受路径白名单、命令护栏与审计日志约束。

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![MCP](https://img.shields.io/badge/MCP-2.x-000000)](https://modelcontextprotocol.io/)
[![Tests](https://img.shields.io/badge/tests-222%20passing-4c1)](#运行测试)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)](#环境要求)

[English](README.md) · **简体中文**

</div>

---

## 目录

- [这是什么](#这是什么)
- [为什么需要它](#为什么需要它)
- [快速开始](#快速开始)
- [接入客户端](#接入客户端)
- [部署](#部署)
- [配置项](#配置项)
- [工具清单](#工具清单)
- [工作原理](#工作原理)
- [安全模型](#安全模型)
- [与透明加密（DLP）共存](#与透明加密dlp共存)
- [开发](#开发)
- [排障](#排障)
- [参与贡献](#参与贡献)
- [许可证](#许可证)

---

## 这是什么

大多数 AI 集成方案是"本地智能体主导 + 调用云端工具"。LocalHands 把这个方向反了过来：
推理跑在云端平台上——飞书 Aily、Kimi、Claude，或任何 MCP 客户端——而这个守护进程，
是它在你工作站上借用的那双手。

```
   云端智能体  ──►  MCP over HTTPS  ──►  隧道  ──►  LocalHands  ──►  你的机器
                                                     │
                          限流 → Bearer 令牌 → 路径白名单 → 命令护栏 → 审计日志
```

23 个工具、一个配置文件，无遥测，除你自己选择的隧道外不依赖任何外部服务。

## 为什么需要它

`claude mcp serve` 同样能把本地机器通过 MCP 暴露出去，对很多人来说已经够用。
LocalHands 用覆盖面换取一个更窄、更受约束的暴露面：

| | `claude mcp serve` | LocalHands |
|---|---|---|
| 每轮对话的工具 schema | 30 个工具、约 70 000 字符（约 2 万 token） | 23 个工具，全部围绕"操作工作站" |
| 身份认证 | 无 | Bearer 令牌，常数时间比对 |
| 文件系统范围 | 不受限 | 白名单，先解析软链接再校验 |
| 审计留痕 | 无 | JSONL，每次调用一行，自动轮转 |
| 二进制传输 | 经过模型上下文 | 带外 HTTP，一次性 URL |

那个 token 数字比看上去更要命：这部分上下文**每一轮都要付一次**，而其中绝大多数
与"操作一台机器"毫无关系（仅 `Workflow` 一个工具就有 19 378 字符）。

---

## 快速开始

五分钟，从零到让云端智能体接管你的文件。

### 环境要求

- **Python 3.10+**
- **Windows 10/11**（主要目标平台）或 **Linux**——桌面类工具与进程处理针对 Windows 调优，
  其余部分可移植
- 若希望守护进程自己对外发布，需要一个隧道程序：[`ngrok`](https://ngrok.com/download)
  或 [`cloudflared`](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/)
- *可选：* 将 [ripgrep](https://github.com/BurntSushi/ripgrep) 放进 `PATH`——`grep`
  会自动使用它，没有则回退到纯 Python 匹配器

### 1. 安装

```powershell
git clone https://github.com/newcovid/LocalHands.git
cd LocalHands

python -m venv .venv
.venv\Scripts\python.exe -m pip install -e .
```

<details>
<summary>Linux / macOS</summary>

```bash
git clone https://github.com/newcovid/LocalHands.git
cd LocalHands

python3 -m venv .venv
.venv/bin/python -m pip install -e .
```

下文命令中把 `.venv\Scripts\python.exe` 换成 `.venv/bin/python` 即可。
</details>

### 2. 配置

```powershell
copy config.example.yaml config.yaml
```

只有两项是必填，其余都有可用默认值。

```yaml
# 生成一个随机令牌：
#   python -c "import secrets; print(secrets.token_urlsafe(32))"
auth_token: "在这里粘贴一个足够长的随机令牌"

# 所有文件类工具都被限制在这些目录内。
allowed_paths:
  - "C:/Users/you/projects"
  - "%TEMP%"
```

> [!IMPORTANT]
> `run_bash` 在设计上就是任意代码执行，因此 `auth_token` 等同于这台机器的 shell 密码。
> 请随机生成、不要提交进版本库（`config.yaml` 已在 `.gitignore` 中），一旦泄露立即更换。

建议把 `%TEMP%` 也加进白名单：图片暂存与 DLP 重新导出都会落在那里。

### 3. 先自检，再启动

```powershell
.venv\Scripts\python.exe -m localhands --config config.yaml --check
```

它会校验配置、检查依赖、确认端口空闲、确认隧道程序可执行，并打印出届时真正会提供的内容，
然后直接退出，不启动任何服务。

```
============================================================
  localhands v1.0.0 — Self-Check
============================================================

✅ All checks passed.
   Port:       127.0.0.1:8765
   Tools:      23 declared (read_file, write_file, edit_file, ...)
   DLP mode:   auto (some tools are withheld when no encryption is found)
   Transports: sse, streamable_http
   ...
```

### 4. 运行

```powershell
.venv\Scripts\python.exe -m localhands --config config.yaml
```

以包方式安装后，直接用 `localhands --config config.yaml` 也可以。

| 参数 | 作用 |
|---|---|
| `--config`、`-c` | YAML 配置路径（默认 `config.yaml`） |
| `--check` | 只做校验并输出报告，不启动服务 |
| `--verbose`、`-v` | 输出 DEBUG 级日志 |
| `--tunnel` / `--no-tunnel` | 本次运行覆盖 `tunnel.enabled` |

确认它活着：

```powershell
curl http://127.0.0.1:8765/health
```

```json
{"status":"ok","server":"localhands","version":"1.0.0","tool_count":22,"tools":["read_file", "..."],"dlp_handling":false}
```

### 5. 对外发布

守护进程只监听回环地址，必须有东西把它送上公网，云端智能体才够得着。

**让守护进程自己管隧道**（推荐——一个进程、一套生命周期）：

```yaml
tunnel:
  enabled: true
  provider: ngrok          # ngrok | cloudflared | custom
  executable: ""           # 留空 = 在 PATH 中查找
  domain: ""               # 如果你的套餐有固定域名
```

此时 `python -m localhands --config config.yaml` 会同时拉起两者，隧道随守护进程一起退出，
并且 `public_base_url` 会从隧道自身的 API 自动填入——传输类工具需要它才能给出绝对 URL。

**或者自己跑隧道**，再告诉守护进程它在哪：

```yaml
tunnel:
  enabled: false
public_base_url: "https://your-domain.example"
```

---

## 接入客户端

把这个 URL 注册到你的 MCP 客户端：

```
https://<你的域名>/mcp?token=<auth_token>
```

| 端点 | 方法 | 用途 |
|---|---|---|
| `/mcp` | `GET` `POST` `DELETE` | Streamable HTTP 传输——**优先用这个** |
| `/sse` | `GET` | 旧的 HTTP+SSE 传输 |
| `/messages/` | `POST` | 与 `/sse` 配套的 JSON-RPC 通道 |
| `/health` | `GET` | 存活探测与实际工具列表——**公开，不需要令牌** |
| `/` | `GET` | 服务信息、传输方式、白名单 |
| `/download/{ticket}` | `GET` | 一次性字节拉取（票据即凭证） |
| `/upload/{ticket}` | `PUT` `POST` | 一次性字节推送（票据即凭证） |

两种传输同时在跑，所以已经注册到 `/sse` 的客户端可以继续用，新客户端指向 `/mcp` 即可。
新接入一律优先 Streamable HTTP：SSE 需要长期挂着一条连接，而隧道会掐掉空闲连接，
客户端随后复用这个已死的会话就会卡住。（`sse_ping_interval` 心跳可以缓解这个问题，
供只能走 SSE 的客户端使用。）

认证支持两种写法：

```
Authorization: Bearer <auth_token>     # 推荐
?token=<auth_token>                    # 供那些只能填一个 URL 的客户端
```

设 `allow_query_token: false` 可强制只走请求头。

---

## 部署

### Windows —— 重启并验证

```powershell
powershell -ExecutionPolicy Bypass -File scripts\restart.ps1
```

`scripts/restart.ps1` 会从 `config.yaml` 里读出端口，杀掉占用该端口的进程，
清理残留的 `ngrok`/`cloudflared`，以分离方式重新拉起守护进程——然后
**轮询 `/health` 直到真的有响应**才报告成功。它不会假设"我启动的进程一定活了下来"。

退出码 `0` 表示健康。失败时，原因与两份日志的尾部会写入 `var/logs/restart.txt`。

### Windows —— 开机自启

用任务计划程序，一条命令搞定：

```powershell
schtasks /Create /TN LocalHands /SC ONLOGON /RL HIGHEST /F `
  /TR "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\path\to\LocalHands\scripts\restart.ps1"
```

### Linux —— systemd

```ini
# /etc/systemd/system/localhands.service
[Unit]
Description=LocalHands MCP daemon
After=network-online.target

[Service]
Type=simple
User=youruser
WorkingDirectory=/opt/localhands
ExecStart=/opt/localhands/.venv/bin/python -m localhands --config config.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now localhands
```

### 运行期数据

守护进程写出的一切都在 `var/` 下，该目录已被 gitignore：

```
var/logs/ops.log       JSONL 审计记录——每次工具调用一行，超过 log_max_bytes 自动轮转
var/logs/runtime.log   守护进程 stdout，每次重启清空
var/logs/tunnel.log    隧道子进程输出
var/logs/restart.txt   最近一次 restart.ps1 的结果
var/trash/             delete_path 的回收站，按时间戳分文件夹
```

想看智能体到底做了什么，一条命令：

```powershell
Get-Content var\logs\ops.log -Tail 20 | ConvertFrom-Json | Format-Table timestamp, tool, status
```

---

## 配置项

`config.example.yaml` 是带完整注释的模板，复制后按需修改。除
[快速开始](#2-配置)里点名的那两项外，下面所有键都是可选的。

<details open>
<summary><b>认证与范围</b></summary>

| 键 | 默认值 | 含义 |
|---|---|---|
| `auth_token` | *（必填）* | 所有 MCP 调用的 Bearer 凭证，等同 shell 密码 |
| `allowed_paths` | *（必填）* | 文件类工具可触及的目录，支持环境变量展开（`%TEMP%`、`$HOME`） |
| `allow_query_token` | `true` | 除请求头外，也接受 `?token=` |
| `host` | `127.0.0.1` | 监听地址，建议保持回环并在前面放隧道 |
| `port` | `8765` | TCP 端口 |

</details>

<details>
<summary><b>传输与限额</b></summary>

| 键 | 默认值 | 含义 |
|---|---|---|
| `transports` | `["sse", "streamable_http"]` | 提供哪些 MCP 传输，可同时开启 |
| `max_request_body_size` | `4194304` | Streamable HTTP 请求体上限（4 MiB） |
| `sse_ping_interval` | `15` | SSE 心跳秒数，`0` 关闭 |
| `max_file_size` | `1048576` | 单次 `read_file` 返回的最大字节数 |
| `bash_timeout` | `30` | `run_bash` 默认超时，单次调用最多可申请 2 倍 |
| `rate_limit` | `60` | 每分钟请求数，同时也是突发容量 |

</details>

<details>
<summary><b>二进制传输通道</b></summary>

| 键 | 默认值 | 含义 |
|---|---|---|
| `public_base_url` | `""` | 智能体可访问的公网源，托管 ngrok 隧道时自动填充 |
| `transfer_ticket_ttl` | `300` | 一次性传输票据的有效秒数 |
| `upload_max_bytes` | `104857600` | 允许接收的最大上传体（100 MB） |

</details>

<details>
<summary><b>对外下载（<code>download_file</code>）</b></summary>

| 键 | 默认值 | 含义 |
|---|---|---|
| `download_allowed_schemes` | `["https","http"]` | 允许的 URL 协议 |
| `download_allowed_hosts` | `[]` | 留空表示允许任意公网主机；列入其中的主机同时豁免私网地址检查 |
| `download_max_bytes` | `52428800` | 体积上限（50 MB） |
| `download_timeout` | `60` | 单次请求超时秒数 |

无论名单怎么配，回环、链路本地与私有地址一律拒绝——没有这道检查，
远端智能体就能用这个工具探测你的内网。每一跳重定向都会重新校验（最多 5 跳）。

</details>

<details>
<summary><b>安全护栏</b></summary>

| 键 | 默认值 | 含义 |
|---|---|---|
| `command_guard_enabled` | `true` | 拒绝一小批不可逆的 shell 命令 |
| `denied_command_patterns` | `[]` | 追加到内置列表之后的额外拒绝正则 |
| `trash_dir` | `./var/trash` | `delete_path` 的移动目标，留空则删除即永久 |
| `screenshot_enabled` | `true` | 设为 `false` 会彻底撤下 `screenshot` 工具 |
| `log_file` | `./var/logs/ops.log` | JSONL 审计日志 |
| `log_max_bytes` | `5242880` | 超过则轮转为 `<log_file>.1`，`0` 关闭 |

</details>

<details>
<summary><b>图片、搜索、DLP、隧道</b></summary>

| 键 | 默认值 | 含义 |
|---|---|---|
| `image_max_edge` | `1568` | 缩放前的最长边；视觉 token 开销随分辨率增长 |
| `image_jpeg_quality` | `85` | 初始 JPEG 质量 |
| `max_image_bytes` | `1572864` | 反复重编码直到结果落入该上限 |
| `ripgrep_path` | `""` | 显式指定 `rg`；留空则先查 `PATH`，再查内置副本，最后回退 Python |
| `dlp_mode` | `auto` | `auto` 抽样白名单探测密文，`on`/`off` 直接下结论 |
| `encrypted_file_markers` | `[]` | 十六进制魔数前缀，留空用内置默认值 |
| `staging_dir` | `""` | 受保护应用导出明文的目录，留空则用 `%TEMP%/localhands_staging` |
| `tunnel.*` | 见模板 | 提供商、可执行文件、域名、额外参数、代理剥离、启动超时 |

</details>

---

## 工具清单

共**声明** 23 个工具；实际对外通告的数量取决于这台机器的情况
（见[工具列表不是固定的](#工具列表不是固定的)）。👁 标记的三个是坐在电脑前的人
**会察觉到**的，其余都是静默操作。

<details open>
<summary><b>文件</b> —— 8 个</summary>

| 工具 | 说明 |
|---|---|
| `read_file` | 默认带行号；支持 `offset`/`limit` 分页；拒绝二进制与 DLP 密文 |
| `read_many_files` | 批量读取——一次往返代替 N 次；每个路径单独报告自己的错误 |
| `write_file` | 整体覆盖内容，自动创建父目录 |
| `edit_file` | 精确字符串替换，默认**要求唯一匹配** |
| `multi_edit` | 对同一文件的多处编辑，按顺序原子应用 |
| `move_path` / `copy_path` | 源与目标两端都校验白名单；`copy_path` 支持递归 |
| `delete_path` | **默认进回收站**并返回 `trash_path`；`permanent=true` 才真正删除 |

</details>

<details open>
<summary><b>搜索</b> —— 5 个</summary>

| 工具 | 说明 |
|---|---|
| `glob` | 支持 `*`、`?`、`**`；按修改时间由新到旧排序 |
| `grep` | 有 ripgrep 时优先使用；支持 `content` / `files_with_matches` / `count` 三种模式 |
| `list_directory` | 名称、类型、大小、修改时间（同时给出 epoch 与 ISO-8601） |
| `get_project_tree` | 遵循 `.gitignore`，跳过构建与缓存目录 |
| `scan_encrypted` | 列出被 DLP 驱动加密因而不可读的文件——*仅在检测到 DLP 时提供* |

</details>

<details open>
<summary><b>Shell、传输、多媒体、网络、桌面</b> —— 10 个</summary>

| | 工具 | 说明 |
|---|---|---|
| **Shell** | `run_bash` | 返回 stdout、stderr、退出码；不可逆命令有护栏；超时按进程树杀 |
| **传输** | `prepare_download` | 生成一次性 URL，把本地文件按原始字节取走 |
| | `prepare_upload` | 生成一次性 URL，把字节写入本机 |
| **多媒体** | `read_image` | 先缩放，再返回 URL——绝不返回像素 |
| | `process_image` | 裁剪、缩放、格式转换；写入 `dest_path`，不产生任何传输 |
| | `image_info` | 格式、色彩模式、尺寸、透明通道、EXIF 方向——不复制、不传输 |
| 👁 | `screenshot` | 捕获此刻屏幕上的内容 |
| **网络** | `download_file` | 由守护进程自己去取 URL，字节不进入上下文 |
| **桌面** 👁 | `open_path` | 用系统关联的应用打开文件或文件夹 |
| 👁 | `notify` | 在用户屏幕上弹出提示框 |

</details>

每个工具还带有标准 MCP `annotations`（`readOnlyHint`、`destructiveHint`、
`idempotentHint`、`openWorldHint`），以及两个本地 `_meta` 提示 `userVisible` 与
`readsScreen`。它们集中在一张表里——[`tools/policy.py`](src/localhands/tools/policy.py)
——所以"这个服务端能在不询问我的情况下对我的机器做什么"，一屏就能看完。

---

## 工作原理

### 二进制数据绝不经过模型上下文

这是决定其他一切的设计取舍。

MCP 把工具参数和结果都当作文本传递，这对字节流是灾难性的：

- **模型 → 本地。** 模型必须把 base64 *生成*为工具参数，于是每个字节都是**输出** token。
  一张 500 KB 的图片约 680 000 字符：几十万输出 token，几十秒生成时间。
- **本地 → 模型。** 字节作为工具**结果**返回。若客户端能把 MCP `ImageContent`
  解码成真正的图像，只需付图像本身的视觉 token；但有些客户端会把结果落盘成 JSON
  再当文本读回来，那就是全额文本价。这属于客户端行为，不能假定。

所以 `prepare_download` 与 `prepare_upload` 只签发**一次性 URL**，并返回一条可直接执行的
`curl` 命令。智能体在自己的环境里搬文件，进入上下文的只有一个短 URL。
无论图片多大，`read_image` 返回的载荷都在 760 字符左右。

更大的收益在于这条通道与格式无关：PDF、压缩包、电子表格走的是同一条路，
于是 `read_file` 只支持文本这件事就不再要紧了。

### 用一次性票据，而不是主令牌

这个 URL 会被交给远端沙箱用 `curl` 去取，所以它携带的任何凭证都会留在那个沙箱的
shell 历史里。而一张票据是 32 字节随机数，作用域被限定为
**一个文件、一个方向、一次使用、几分钟有效**。长期有效的 `auth_token` 从不离开本机。
签发与兑换时都会重新校验路径白名单。

### 工具列表不是固定的

启动时，守护进程会在白名单目录里抽样查找透明加密驱动留下的密文魔数。干净的机器上什么也
找不到，于是 `scan_encrypted` 根本不会被通告，相关 DLP 说明也不会送达智能体——
向它描述一辈子遇不到的密文，纯属浪费上下文。`screenshot_enabled: false`
以同样的方式撤下屏幕捕获。`/health` 报告的是*实际*提供的内容。

### 服务端级别的说明

除了逐个工具的 schema，服务端还会在 initialize 响应里返回一段 `instructions`——
客户端通常会把它并入系统提示词，也就是说它在模型*挑选工具之前*就已经到位。
这段内容讲的是整体性的事：字节走 HTTP 而不走上下文、文件访问受白名单限制、
以及哪三个工具会被坐在机器前的人察觉到。

---

## 安全模型

五道防线，按请求经过的顺序：

1. **限流**——令牌桶，最外层，在解析任何内容之前生效。
2. **Bearer 令牌**——请求头或 `?token=`，常数时间比对。`/health` 是公开的；
   `/download` 与 `/upload` 改用各自的一次性票据认证，从而避免把长期令牌放进 URL。
3. **路径白名单**——每个路径都先完全解析（软链接、junction、`..`）*再*做前缀校验，
   因此指向外部的软链接会被拒绝，而不是被跟随。
4. **命令护栏**——针对不可逆命令的拒绝名单：整盘操作、递归删除盘符根目录、关机、
   删除注册表配置单元，以及把下载内容直接管道进 shell。
5. **审计日志**——JSONL，每次调用一行，支持轮转。

> [!WARNING]
> **必须说清楚它不是什么。** `run_bash` 在设计上就是任意代码执行，因此认证令牌等同于
> 这台机器的 shell 密码。命令护栏防的是"模型读错指令或被注入指令后干出不可逆的事"，
> **不是**对抗性安全边界——任何拿到 shell 的人都能轻易绕过正则。
> 若需要硬边界，请把守护进程放进虚拟机或容器里运行。

---

## 与透明加密（DLP）共存

**如果你的机器上没有这类驱动，请跳过本节。** 在默认的 `dlp_mode: auto` 下，
守护进程会在启动时抽样白名单目录，且优先针对这类策略实际会保护的文档与图片格式。
什么也没找到，它就把整个话题隐去。用 `dlp_mode: on | off` 可以强制指定结论。

企业终端上经常装有透明加密过滤驱动。由*受保护*应用写出的文件，到这个守护进程手里时是
**密文**；否则 `read_file` 会返回好几 KB 的乱码——而模型随后会一本正经地基于噪声推理，
并按全价计费。

有两个实测结论决定了什么才真正有用：

- **复制不会解密。** `shutil.copyfile`、`cmd copy` 和 `Copy-Item` 产出的都是仍然加密的副本，
  放在 `%TEMP%` 或任何别处都一样。密文*就是*文件内容，位置无关紧要。
- **`%TEMP%` 通常在写入时被排除。** 受保护应用往 `%TEMP%` 里"另存为"时写出的是明文，
  因为驱动会跳过该路径。

因此守护进程用魔数识别这种情况，并返回 `FileEncrypted` 错误，同时指明唯一可行的补救办法：
从拥有该文件的应用里重新导出到 `staging_dir`。在规划一批文档的处理之前先跑一次
`scan_encrypted`，一次调用就能知道哪些可读，而不必一个个失败着去发现。

---

## 开发

### 项目结构

```
pyproject.toml            打包、pytest 与 ruff 配置
config.example.yaml       带注释的模板，复制为 config.yaml
scripts/restart.ps1       重启并验证（Windows）
src/localhands/
  daemon.py               入口、ASGI 路由、传输层、隧道生命周期
  config.py               带校验的强类型配置
  security.py             认证、限流、PathGuard、CommandGuard、票据、审计日志
  transfer.py             /download 与 /upload 的字节流
  tunnel.py               隧道监管（ngrok / cloudflared / custom）
  tools/
    base.py               ToolProvider 协议、LocalProvider、ok()/err()
    __init__.py           注册表与分发器
    policy.py             逐工具标注：只读、破坏性、用户可见
    instructions.py       initialize 响应中下发的服务端级说明
    encryption.py         DLP 检测与探测
    files.py  search.py  shell.py  xfer.py  media.py  net.py  desktop.py
tests/                    pytest 套件；不需要守护进程、网络或隧道
var/                      运行期数据——日志、回收站（已 gitignore）
```

### 运行测试

```powershell
.venv\Scripts\python.exe -m pip install -e ".[dev]"
.venv\Scripts\python.exe -m pytest tests/ -q
```

222 个测试，全都不需要运行中的守护进程、网络或隧道。一切都在进程内基于 `tmp_path` 构建，
并且刻意从不读取真实的 `config.yaml`。

```powershell
.venv\Scripts\python.exe -m pytest tests/test_tools.py::TestEditFile -q   # 单个类
.venv\Scripts\python.exe -m pytest tests/ -k "encrypted" -q               # 按名称筛选
```

Lint 规则写在 `pyproject.toml` 里（ruff 不是声明的依赖，需另行安装）。
当前代码库零告警，请保持：

```powershell
ruff check .
```

### 新增一个工具

继承 `LocalProvider`，声明 `name` 与 `tools`，并为每个工具实现一个名为 `_<tool_name>`
的方法。把这个类注册进 `PROVIDER_CLASSES`，再到 `tools/policy.py` 的 `POLICIES`
里加一条，工具才会带上正确的标注。分发器、审计日志与错误兜底都不需要改动。

同步方法会自动被放到工作线程上执行，所以慢速文件系统不会拖住事件循环；
写成 `async def` 的方法则直接 await。

同一个接缝也是代理**上游 MCP 服务端**的方式：基于 stdio 或 HTTP 客户端实现
`ToolProvider`，给工具名加上命名空间前缀，对路径参数套用 `PathGuard`，
然后与本地 provider 并列注册即可。

### 关于 `mcp` 依赖的说明

`mcp>=2.0` 这个下限是有实际约束力的，不是随手写的卫生条款。2.x 是对 1.x API 的重写，
而非兼容性升级：底层 `Server` 改用 `on_*` 处理器而非装饰器，返回值不会自动包装，
模型字段一律改为 snake_case。

---

## 排障

<details>
<summary><b>守护进程说自己启动了，但没有任何响应</b></summary>

请用 `scripts/restart.ps1` 而不是手工启动——它会轮询 `/health` 并如实报告。
若失败，`var/logs/restart.txt` 里有原因以及两份日志的尾部。

Windows 上的一个常见成因：被重定向的 stdout 会以本地区域编码打开，
非 ASCII 日志输出会在进程绑定端口之前就把它杀掉。守护进程会在启动时强制
stdout/stderr 为 UTF-8，正是为了避免这一点。
</details>

<details>
<summary><b>空闲一段时间后，客户端第一次调用就卡住</b></summary>

这是 SSE 的典型故障：空闲连接在隧道某处被掐断，客户端复用了这个已死的池化会话，
调用便永远不返回。把客户端指向 `/mcp`（Streamable HTTP）即可——它的交换以请求为界，
根本不存在会丢失的空闲连接。若必须留在 SSE，请保持 `sse_ping_interval` 大于零。
</details>

<details>
<summary><b>ngrok 立刻退出并报 <code>ERR_NGROK_9009</code></b></summary>

ngrok 免费版在设置了 `http_proxy`/`https_proxy` 时会拒绝启动。保持默认的
`tunnel.strip_proxy_env: true`——它只从隧道子进程的环境里剥离这些变量，
你其他工具的代理设置不受影响。
</details>

<details>
<summary><b>下载下来的是一个 HTML 页面，而不是文件</b></summary>

ngrok 免费版会对"看起来像浏览器"的请求返回一个中间页（`ERR_NGROK_6024`）。
传输类工具返回的 `curl` 字段里已经带上了 `ngrok-skip-browser-warning` 头——
请原样执行那条命令，不要自己拼一条。
</details>

<details>
<summary><b><code>read_file</code> 返回 <code>FileEncrypted</code></b></summary>

该文件由透明加密驱动接管，复制它没有用。请参见
[与透明加密（DLP）共存](#与透明加密dlp共存)。
</details>

<details>
<summary><b>项目内的某个路径被拒绝了</b></summary>

`PathGuard` 会先解析软链接和 junction 再校验前缀，因此一个名字看起来没问题、
但指向 `allowed_paths` 之外的链接同样会被拒绝。把真实目标目录加进白名单，或把文件移进来。
</details>

---

## 参与贡献

欢迎在 [github.com/newcovid/LocalHands](https://github.com/newcovid/LocalHands)
提交 issue 与 pull request。

提 PR 之前请确认：

- `.venv\Scripts\python.exe -m pytest tests/ -q` 全部通过
- `ruff check .` 无告警
- 新增工具带有对应的 `POLICIES` 条目，以及一个走真实分发器的测试

请不要在补丁中带入机器专属路径、令牌或隧道域名——`config.yaml` 与 `var/`
被 gitignore 正是为此。

## 许可证

[MIT](LICENSE) © newcovid
