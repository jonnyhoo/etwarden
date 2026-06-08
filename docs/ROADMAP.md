# etwarden 超越 SunnyNet 路线图

> 目标：全方位超越 SunnyNet + SunnyNet-wpf，成为最强 Windows 进程级网络抓包工具。

## 1. 竞品分析

### 1.1 SunnyNet 架构

```
SunnyNet Go库 (third_party/SunnyNet/)
├── api.go (180符号) — CGO导出接口
├── Api/SunnyNet.go — 高层API (SetRequestHeader, GetResponseStatusCode等)
├── Api/CertificateManager.go — CA证书管理
├── src/nfapi/ — 内核驱动交互层
│   ├── EventHandler.go — SetHookProcess, AddPid, DelPid, GetTcpConnectInfo
│   ├── Driver.go — 回调: tcpConnectRequest, tcpConnected, tcpClosed, tcpReceive, tcpSend
│   └── nfdriver.go — NF_RULE, NF_PORT_RANGE等结构体
├── src/crypto/tls/ — 魔改Go TLS库(支持MITM证书签发)
├── src/CrossCompiled/ — 平台适配(windows/linux/darwin)
└── public/public.go — 工具函数

SunnyNet-wpf后端 (backend/)
├── SunnyNet.go (1188行) — 主回调: HttpCallback, 内容解码(gzip/br/deflate)
├── TLSFingerprint.go (489行) — JA3/JA3N/JA4 TLS指纹
├── ReplaceRules.go (893行) — 流量替换规则引擎
├── InterceptRules.go (164行) — 拦截/断点规则
├── HOSTSRules.go (87行) — Hosts域名重定向
├── Config.go (1134行) — 配置 + yaegi脚本引擎
├── PbSchema.go (495行) — Protobuf schema解析
├── PbToJson.go — Protobuf转JSON
├── Find.go (771行) — 全流量搜索(UTF8/GBK/HEX/Base64/PB/Int/Float)
├── MapHash/hash.go (1237行) — 请求存储 + 重放
├── CreateRequestCode.go — 请求代码生成(Java/JS/Python/C#)
├── RequestCertificate.go (136行) — 证书管理
├── process.go (41行) — 进程管理(枚举/按PID过滤)
└── dll_bridge.go/dll_exports.go — DLL桥接WPF前端

WPF前端 (src/) — 24个XAML + 63个C#文件
```

### 1.2 SunnyNet 核心弱点

| 弱点 | 原因 |
|------|------|
| 进程关联不精确 | nfapi靠端口匹配猜PID，非直接关联 |
| 全局抓包 | 无法只监控目标进程，性能浪费 |
| 依赖内核驱动 | 需要签名驱动，部署复杂 |
| 无DNS监控 | 不记录DNS查询/响应 |
| 无被动情报 | 不收集TLS SNI/证书链等元数据 |
| Go GC延迟 | 高流量下GC暂停影响实时性 |
| GUI绑定 | 核心功能与WPF UI紧耦合 |

### 1.3 etwarden 现有优势

| 优势 | 实现 |
|------|------|
| 精确PID关联 | ETW内核级直接提供PID |
| 零侵入 | 纯ETW被动监听，不注入驱动 |
| DNS全量监控 | Microsoft-Windows-DNS-Client ETW provider |
| 管道化输出 | NDJSON stdout，可与任意工具链组合 |
| Rust性能 | 零成本抽象，无GC |
| 模块化架构 | capture/parser/filter/output 分层解耦 |

---

## 2. 四层架构设计

```
┌──────────────────────────────────────────────────────────────┐
│ Layer 4: 高级分析                                             │
│  TLS指纹(JA3/JA4) · Protobuf解析 · 全流量搜索 · 脚本引擎     │
├──────────────────────────────────────────────────────────────┤
│ Layer 3: 流量控制                                             │
│  替换规则 · 拦截断点 · Hosts重定向 · 请求重放                  │
├──────────────────────────────────────────────────────────────┤
│ Layer 2: HTTPS解密                                            │
│  rustls-mitm MITM proxy · 系统代理注入 · 内容解码              │
├──────────────────────────────────────────────────────────────┤
│ Layer 1: ETW被动情报 (已实现)                                  │
│  TCP/IP连接 · DNS · NDIS帧DPI · TLS SNI · 进程树              │
└──────────────────────────────────────────────────────────────┘
```

每层独立可用，可选择性启用。

---

## 3. Phase 1: ETW增强（被动情报层）

### 3.1 TLS SNI + 指纹识别

**来源**: `backend/TLSFingerprint.go` (489行)

**目标文件**: `src/parser/dpi/tls/fingerprint.rs` (新建)

**算法细节**:

#### 3.1.1 Client Hello 解析

输入：NDIS原始帧中的TCP payload，识别为TLS Client Hello。

```
TLS Record:
  [0]    = 0x16 (Handshake)
  [1..2] = TLS版本
  [3..4] = 长度
  [5]    = 0x01 (ClientHello)
  [6..8] = ClientHello长度(3字节)

ClientHello body:
  [0..1]  legacyVersion (uint16)
  [2..33] random (32字节)
  [34]    sessionIDLength
  [35..35+sidLen] sessionID
  [..]    cipherSuitesLength (uint16)
  [..]    cipherSuites (每2字节一个)
  [..]    compressionMethodsLength
  [..]    compressionMethods
  [..]    extensionsLength (uint16)
  [..]    extensions (循环)
```

#### 3.1.2 Extension 解析

| Extension ID | 名称 | 解析内容 |
|-------------|------|---------|
| 0x0000 | SNI (server_name) | 域名字符串 |
| 0x000a | Supported Groups | 椭圆曲线列表 (uint16[]) |
| 0x000b | EC Point Formats | 点格式 (uint8[]) |
| 0x000d | Signature Algorithms | 签名算法 (uint16[]) |
| 0x0010 | ALPN | 应用层协议 (string[]) |
| 0x002b | Supported Versions | TLS版本列表 (uint16[]) |

#### 3.1.3 SNI 解析

```
SNI Extension data:
  [0..1] listLength
  循环:
    [0]   nameType (0 = hostname)
    [1..2] nameLength
    [3..3+nameLength] hostname字符串
```

#### 3.1.4 ALPN 解析

```
ALPN Extension data:
  [0..1] listLength
  循环:
    [0]   protocolLength
    [1..1+protocolLength] protocol字符串 (如 "h2", "http/1.1")
```

#### 3.1.5 JA3 指纹

```
JA3 = MD5(
  legacyVersion + "," +
  cipherSuites(十进制, "-"分隔) + "," +
  extensions(十进制, "-"分隔) + "," +
  supportedGroups(十进制, "-"分隔) + "," +
  ecPointFormats(十进制, "-"分隔)
)

JA3N = 同JA3，但extensions排序后再拼接
```

#### 3.1.6 JA4 指纹

```
JA4前缀 = "t" + versionCode + sniMarker + cipherCount(2位) + extCount(2位) + alpnCode

versionCode:
  TLS 1.3 → "13"
  TLS 1.2 → "12"
  TLS 1.1 → "11"
  TLS 1.0 → "10"
  SSL 3.0 → "s3"

sniMarker:
  有域名 → "d"
  IP地址或空 → "i"

alpnCode:
  "h2"    → "h2"
  "h3"    → "h3"
  "http/1.1" → "h1"
  "http/1.0" → "h0"
  其他    → 首字符+末字符(小写)
  无      → "00"

JA4  = prefix + "_" + sha256(sortedCiphersHex)[:12] + "_" + sha256(sortedExtsHex + "_" + sigAlgsHex)[:12]
JA4O = 同JA4，但使用原始顺序(非排序)
JA4R = prefix + "_" + sortedCiphersHex + "_" + sortedExtsHex + "_" + sigAlgsHex (原始值)
JA4RO = 同JA4R，但使用原始顺序

GREASE值过滤: value & 0x0f0f == 0x0a0a && (value>>8) as u8 == value as u8
```

#### 3.1.7 数据结构

```rust
// src/parser/tls_fingerprint.rs

pub struct TlsClientHello {
    pub legacy_version: u16,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub sni: Option<String>,
    pub supported_groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub alpn: Vec<String>,
    pub raw: Vec<u8>,
}

pub struct TlsFingerprint {
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub legacy_version: u16,
    pub highest_version: u16,
    pub ja3_text: String,
    pub ja3_hash: String,      // MD5 hex
    pub ja3n_text: String,
    pub ja3n_hash: String,     // MD5 hex
    pub ja4: String,
    pub ja4o: String,
    pub ja4r: String,
    pub ja4ro: String,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub raw_client_hello_hex: String,
}

pub fn parse_tls_client_hello(payload: &[u8]) -> Option<TlsClientHello>;
pub fn build_tls_fingerprint(hello: &TlsClientHello) -> TlsFingerprint;
```

#### 3.1.8 集成点

- `src/parser/dpi.rs` — 在 `apply_dpi()` 中检测到TLS Client Hello后调用
- `src/parser/types.rs` — 新增 `TlsFingerprint` 字段到 `NetEvent` 或独立事件
- `src/output/schema.rs` — 新增 `TlsEventLine` 输出格式

#### 3.1.9 依赖

- `md-5` crate (MD5计算，或使用 `md5` crate)
- `sha2` crate (SHA-256计算)
- 无其他外部依赖

### 3.2 HTTP 明文 DPI

**目标文件**: `src/parser/dpi/http.rs` (新建)

从NDIS帧中识别明文HTTP请求/响应。

```
HTTP请求检测:
  以 "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE " 开头

提取:
  Method  → 第一个空格前的字符串
  Path    → 第一个空格后到第二个空格或\r\n
  Host    → "Host: " header行
  Version → "HTTP/1.0" 或 "HTTP/1.1"

HTTP响应检测:
  以 "HTTP/1." 开头

提取:
  StatusCode → "HTTP/1.x " 后的3位数字
  ContentType → "Content-Type: " header行
  ContentLength → "Content-Length: " header行
```

### 3.3 进程树关联

**目标文件**: `src/process/tree.rs` (新建)

---

## 4. Phase 2: HTTPS 解密

### 4.1 MITM Proxy 架构

```
目标进程 → [系统代理] → etwarden MITM proxy → 目标服务器
                         │
                         ├─ 左连接: 进程 → proxy (伪造证书)
                         └─ 右连接: proxy → 服务器 (真实证书)

流程:
  1. 设置系统代理指向 localhost:PORT
  2. 进程发起HTTPS请求 → 被代理到本地
  3. proxy收到CONNECT host:443
  4. proxy用rustls-mitm为该host动态签发证书
  5. proxy以伪造证书与进程建立TLS (左连接)
  6. proxy以真实证书与服务器建立TLS (右连接)
  7. 解密后的HTTP内容输出到NDJSON
```

### 4.2 技术选型

| 组件 | crate | 用途 |
|------|-------|------|
| TLS MITM | `http-mitm-proxy` | 动态CA + per-host证书签发 |
| HTTP/1.1解析 | `httparse` | 解析HTTP请求/响应 |
| HTTP/2 | `h2` | HTTP/2帧解析 |
| 异步运行时 | `tokio` | 异步IO |
| 系统代理设置 | `windows` crate (WinHTTP API) | 设置系统代理 |

### 4.3 系统代理注入

```rust
// 使用 WinINet/WinHTTP API 设置系统代理
// windows crate: Win32::NetworkManagement::WindowsFiltering 或注册表方式

// 方法1: 注册表 (立即生效，需刷新)
// HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
//   ProxyEnable = 1
//   ProxyServer = "127.0.0.1:PORT"

// 方法2: WinHTTP API
// WinHttpSetDefaultProxyConfiguration

// 方法3: PAC文件 (更灵活)
// 生成PAC文件，仅代理目标PID的流量
```

### 4.4 内容解码

**来源**: `backend/SunnyNet.go` 第336-397行

```
检测 Content-Encoding header:
  "gzip"    → flate2::read::GzDecoder 解压
  "br"      → brotli::Decompressor 解压
  "deflate" → flate2::read::DeflateDecoder 解压

解压后:
  删除 Content-Encoding header
  删除 Transfer-Encoding header
  更新 Content-Length
```

**Rust crates**: `flate2`, `brotli`

### 4.5 进程级代理策略

```
挑战: 系统代理是全局的，无法只代理特定进程

解决方案:
  1. PAC文件中根据来源IP/端口判断 (不可靠)
  2. 代理层查询ETW连接表，仅处理目标PID的连接
  3. WFP Connect Redirect (需要驱动，Phase 4)

当前方案: 代理所有流量，在proxy层通过ETW关联的连接表过滤PID
  - ETW TcpIp provider 记录了 PID ↔ (srcPort, dstAddr, dstPort) 映射
  - proxy收到连接时，查询本地端口对应的PID
  - 非目标PID的流量直接透传，不拦截
```

---

## 5. Phase 3: 流量控制

### 5.1 替换规则引擎

**来源**: `backend/ReplaceRules.go` (893行)

**目标文件**: `src/rules/replace.rs` (新建)

#### 5.1.1 规则类型

```rust
pub enum ReplaceType {
    Bytes,      // 字节替换 (Base64/HEX/UTF8/GBK)
    File,       // 文件替换 (匹配到URL后返回文件内容)
}

pub struct ReplaceRule {
    pub rule_type: ReplaceType,
    pub source: Vec<u8>,   // 源内容
    pub target: Vec<u8>,   // 目标内容
}
```

#### 5.1.2 替换逻辑

```
对URL匹配:
  遍历所有规则
  如果 URL.contains(source):
    Bytes类型 → URL = URL.replace(source, target)
    File类型 → 直接返回target作为响应体，中断请求

对Body匹配:
  同上，但操作对象是请求/响应体
```

#### 5.1.3 请求/响应重写

```rust
pub struct RequestRewriteOperation {
    pub target: String,      // "URL" / "Header" / "Body"
    pub operation: String,   // "设置" / "删除" / "追加"
    pub key: String,         // Header名 或 留空
    pub value: String,       // 新值
    pub value_type: String,  // "String" / "Base64" / "HEX"
}
```

### 5.2 拦截/断点规则

**来源**: `backend/InterceptRules.go` (164行)

**目标文件**: `src/rules/intercept.rs` (新建)

```rust
pub struct InterceptRule {
    pub enable: bool,
    pub name: String,
    pub direction: InterceptDirection,  // Upstream / Downstream / Both
    pub target: InterceptTarget,        // URL / Header / Body / PID / ProcessName
    pub operator: MatchOperator,        // Equals / Contains / Regex / Prefix / Suffix
    pub value: String,
    pub note: String,
}

pub enum InterceptDirection { Upstream, Downstream, Both }
pub enum InterceptTarget { Url, Header, Body, Pid, ProcessName }
pub enum MatchOperator { Equals, Contains, Regex, StartsWith, EndsWith }
```

#### 匹配逻辑

```
对每个请求/响应:
  遍历所有启用的规则
  检查方向匹配 (上行/下行/双向)
  根据target提取文本:
    URL → 完整URL字符串
    Header → 所有header拼接
    Body → 请求/响应体
    PID → 进程ID字符串
    ProcessName → 进程名
  根据operator匹配:
    Equals → 忽略大小写完全匹配
    Contains → 忽略大小写包含
    Regex → 正则匹配
    StartsWith → 前缀匹配
    EndsWith → 后缀匹配
  匹配成功 → 触发拦截动作 (断开/丢弃/断点暂停)
```

### 5.3 Hosts 规则

**来源**: `backend/HOSTSRules.go` (87行)

**目标文件**: `src/rules/hosts.rs` (新建)

```rust
pub struct HostsRule {
    pub pattern: Regex,   // 源地址正则
    pub target: String,   // 新地址
}

// 匹配: 对请求URL的host部分应用正则替换
// 用途: 将请求重定向到指定服务器
```

### 5.4 屏蔽规则

**来源**: `backend/ReplaceRules.go` 第150-295行

```rust
// HTTP屏蔽
pub struct RequestBlockRule {
    pub enable: bool,
    pub priority: u32,
    pub method: String,        // 匹配的HTTP方法
    pub url_match_type: String, // "包含" / "前缀" / "正则" / "完全匹配"
    pub url_pattern: String,
    pub action: String,         // "断开请求" / "断开响应"
}

// WebSocket屏蔽
pub struct WebSocketBlockRule {
    pub enable: bool,
    pub priority: u32,
    pub method: String,
    pub url_match_type: String,
    pub url_pattern: String,
    pub action: String,         // "断开连接" / "丢弃上行帧" / "丢弃下行帧"
}

// TCP/UDP屏蔽
pub struct SocketBlockRule {
    pub enable: bool,
    pub priority: u32,
    pub protocol: String,       // "TCP" / "UDP"
    pub address: String,
    pub action: String,         // "断开连接" / "丢弃上行" / "丢弃下行"
}
```

### 5.5 请求重放

**来源**: `backend/MapHash/hash.go` (1237行)

**目标文件**: `src/replay/mod.rs` (新建)

```rust
pub struct CapturedRequest {
    pub id: u64,
    pub pid: u32,
    pub method: String,
    pub url: String,
    pub proto: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub response: Option<CapturedResponse>,
    pub tls_fingerprint: Option<TlsFingerprint>,
    pub send_time: DateTime<Utc>,
    pub recv_time: Option<DateTime<Utc>>,
}

pub struct CapturedResponse {
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

// 重放功能
pub fn replay_http(req: &CapturedRequest) -> Result<CapturedResponse>;
pub fn replay_tcp(addr: &str, data: &[u8]) -> Result<Vec<u8>>;
pub fn replay_udp(addr: &str, data: &[u8]) -> Result<Vec<u8>>;
```

### 5.6 规则配置格式

```json5
// etwarden-rules.json
{
  "replace_rules": [
    { "type": "Bytes", "source": "old.example.com", "target": "new.example.com", "encoding": "UTF8" }
  ],
  "intercept_rules": [
    { "enable": true, "direction": "Both", "target": "URL", "operator": "Contains", "value": "ads.example.com", "action": "Drop" }
  ],
  "hosts_rules": [
    { "pattern": ".*\\.example\\.com", "target": "127.0.0.1" }
  ],
  "block_rules": {
    "http": [
      { "enable": true, "priority": 1, "method": "*", "url_pattern": "tracker\\.ad\\.com", "action": "CloseRequest" }
    ],
    "websocket": [],
    "tcp": [],
    "udp": []
  }
}
```

---

## 6. Phase 3.5: WinDivert 增强层（捕获非代理流量）

### 6.1 为什么需要这一层

```
Layer 1 (ETW)     → 被动元数据，能看到连接但看不到内容
Layer 2 (MITM)    → 只能拦截走系统代理的HTTP/HTTPS流量
                     非HTTP进程（自定义TCP/UDP客户端）完全绕过代理

Layer 3 (WinDivert) → 捕获所有TCP/UDP流量，包括：
  - 自定义协议（游戏、RPC、数据库连接）
  - 不走代理的HTTP客户端
  - UDP流量（DNS over UDP, QUIC）
  - 裸TCP流（telnet, SSH, 任意自定义协议）
```

### 6.2 WinDivert 工作原理

```
WinDivert 是一个内核级数据包捕获/修改驱动:
  1. 安装WinDivert内核驱动 (1.x版本自带签名)
  2. 用户态程序通过WinDivert DLL打开"捕获层"
  3. 指定过滤规则 (BPF语法): "tcp.DstPort == 443 and ip.DstAddr != 127.0.0.1"
  4. 匹配的数据包被重定向到用户态
  5. 用户态程序可以 读取/修改/丢弃/重注入 数据包

关键API:
  WinDivertOpen(filter, layer, priority, flags) → handle
  WinDivertRecv(handle, &mut packet) → packet + addr
  WinDivertSend(handle, packet, addr) → 发送/重注入
  WinDivertShutdown(handle, how)
  WinDivertClose(handle)

捕获层:
  WINDIVERT_LAYER_NETWORK       — IP层 (最常用)
  WINDIVERT_LAYER_NETWORK_FORWARD — 转发层
  WINDIVERT_LAYER_FLOW           — 流层 (仅元数据)
  WINDIVERT_LAYER_SOCKET         — Socket层
  WINDIVERT_LAYER_REFLECT        — 反射层
```

### 6.3 与SunnyNet的对比

```
SunnyNet使用nfapi驱动:
  - 需要自己的签名驱动
  - 进程关联靠端口匹配（不精确）
  - 全局拦截所有流量（无法按PID过滤）

etwarden使用WinDivert + ETW:
  - WinDivert 1.x自带签名驱动（零部署成本）
  - ETW提供精确PID关联
  - 可以按PID/进程名过滤，只捕获目标进程流量
  - 与Layer 1/2协同工作
```

### 6.4 架构设计

```
┌─────────────────────────────────────────────────────────┐
│                    etwarden 三层协同                      │
│                                                          │
│  Layer 1: ETW (始终运行)                                  │
│    → 记录所有连接的 PID ↔ (srcPort, dstAddr, dstPort)     │
│    → 维护实时连接表                                       │
│                                                          │
│  Layer 2: MITM Proxy (可选, 仅HTTP/HTTPS)                │
│    → 系统代理 → rustls-mitm → 解密HTTPS内容               │
│                                                          │
│  Layer 3: WinDivert (可选, 捕获非代理流量)                 │
│    → 查询ETW连接表获取PID                                 │
│    → 仅捕获目标PID的TCP/UDP流量                           │
│    → 对非目标PID的包直接放行                               │
│    → 对目标PID的包:                                       │
│       - TCP: 可选重定向到本地TCP代理进行内容分析            │
│       - UDP: 直接读取payload进行DPI                       │
│       - 也可仅读取不修改(被动模式)                         │
└─────────────────────────────────────────────────────────┘
```

### 6.5 目标文件

| 文件 | 类型 | 行数估计 | 说明 |
|------|------|---------|------|
| `src/divert/mod.rs` | 新建 | ~40 | WinDivert模块入口 |
| `src/divert/ffi.rs` | 新建 | ~250 | WinDivert DLL FFI绑定 |
| `src/divert/capture.rs` | 新建 | ~300 | 数据包捕获循环 |
| `src/divert/filter.rs` | 新建 | ~150 | BPF过滤规则生成 + PID过滤 |
| `src/divert/packet.rs` | 新建 | ~200 | IP/TCP/UDP包解析/重构 |

### 6.6 FFI 绑定设计

```rust
// src/divert/ffi.rs

// WinDivert DLL 动态加载 (避免编译时依赖)
// WinDivert.dll + WinDivert.sys 随程序分发

type WinDivertOpenFn = unsafe extern "system" fn(
    filter: *const i8,
    layer: u32,
    priority: i16,
    flags: u64,
) -> *mut c_void;

type WinDivertRecvFn = unsafe extern "system" fn(
    handle: *mut c_void,
    packet: *mut u8,
    packet_len: u32,
    recv_len: *mut u32,
    addr: *mut WinDivertAddress,
) -> i32;

type WinDivertSendFn = unsafe extern "system" fn(
    handle: *mut c_void,
    packet: *const u8,
    packet_len: u32,
    send_len: *mut u32,
    addr: *const WinDivertAddress,
) -> i32;

type WinDivertCloseFn = unsafe extern "system" fn(handle: *mut c_void) -> i32;

type WinDivertShutdownFn = unsafe extern "system" fn(
    handle: *mut c_void,
    how: u32,
) -> i32;

#[repr(C)]
struct WinDivertAddress {
    timestamp: i64,       // 微秒时间戳
    layer: u8,            // 捕获层
    event: u8,            // 事件类型
    flags: u8,            // 标志
    reserved: u8,
    union_data: u64,      // 按layer解释
}

// 动态加载
pub struct WinDivertDll {
    open: WinDivertOpenFn,
    recv: WinDivertRecvFn,
    send: WinDivertSendFn,
    close: WinDivertCloseFn,
    shutdown: WinDivertShutdownFn,
}

impl WinDivertDll {
    pub fn load() -> Result<Self>;
    pub fn open(&self, filter: &str, layer: u32, priority: i16) -> Result<WinDivertHandle>;
}
```

### 6.7 PID 过滤策略

```
WinDivert本身不支持按PID过滤（只支持BPF包过滤）。
但我们可以利用ETW连接表实现精确PID过滤:

方案: 两级过滤
  Level 1: WinDivert BPF过滤 (粗筛)
    - 过滤掉本地回环: "ip.DstAddr != 127.0.0.1 and ip.SrcAddr != 127.0.0.1"
    - 可选: 只捕获特定端口 "tcp.DstPort == 443 or tcp.DstPort == 80"

  Level 2: 用户态PID匹配 (精确)
    - 收到包后，提取 (srcIP, srcPort, dstIP, dstPort, protocol)
    - 查询ETW连接表: 该五元组对应的PID是什么？
    - 如果PID在目标列表中 → 处理该包
    - 如果PID不在目标列表中 → 立即重注入放行

性能优化:
  - ETW连接表是HashMap<OwningFiveTuple, (PID, ...)>
  - 查询O(1)，不构成瓶颈
  - 非目标包的处理路径: recv → 查表 → send (仅两次系统调用)
```

### 6.8 数据包处理流程

```
WinDivertCapture 线程:

loop {
    // 1. 接收匹配的数据包
    (packet, addr) = divert.recv()?;

    // 2. 解析IP/TCP/UDP头
    let parsed = parse_packet(&packet)?;

    // 3. 查询ETW连接表获取PID
    let pid = etw_conn_table.lookup(parsed.five_tuple());

    // 4. PID过滤
    if !target_pids.contains(&pid) {
        divert.send(&packet, &addr)?;  // 放行
        continue;
    }

    // 5. 处理目标进程的包
    match config.mode {
        CaptureMode::Passive => {
            // 仅读取，不修改
            output_dpi_result(parsed, pid);
            divert.send(&packet, &addr)?;  // 原样放行
        }
        CaptureMode::Redirect => {
            // 重定向到本地TCP代理
            redirect_to_local_proxy(&mut packet, &addr, parsed)?;
            divert.send(&packet, &addr)?;
        }
        CaptureMode::Block => {
            // 丢弃（不重注入 = 阻断）
            output_block_event(parsed, pid);
        }
    }
}
```

### 6.9 TCP 重定向（可选）

```
将目标进程的TCP连接重定向到本地代理:

原始: 进程 → dst:443
修改: 进程 → 127.0.0.1:LOCAL_PORT (本地TCP代理)
代理: 本地TCP代理 → dst:443 (转发)

实现:
  1. WinDivert捕获目标PID的TCP SYN包
  2. 修改目标地址为 127.0.0.1:LOCAL_PORT
  3. 保存原始地址到映射表
  4. 重新计算IP/TCP校验和
  5. 重注入修改后的包
  6. 本地代理收到连接，查表获取原始目标
  7. 代理连接到原始目标，双向转发

校验和重算:
  WinDivertHelperCalcChecksums() — WinDivert提供辅助函数
  或手动重算: IP header checksum + TCP/UDP checksum (含伪首部)
```

### 6.10 UDP 处理

```
UDP无法像TCP那样重定向连接，但可以:
  1. 被动读取: 解析UDP payload进行DPI (DNS, QUIC, 自定义协议)
  2. 修改payload: 替换DNS响应、修改QUIC初始包
  3. 丢弃: 不重注入 = 阻断UDP包

QUIC (HTTP/3) 检测:
  UDP dstPort == 443
  payload[0] 首位 == 1 (Long Header)
  解析Connection ID, SNI (QUIC Client Hello中包含TLS扩展)
```

### 6.11 依赖

```toml
# 无Rust crate依赖 — WinDivert通过FFI动态加载DLL

# 运行时需要分发:
#   WinDivert.dll (用户态库)
#   WinDivert.sys (内核驱动, 1.x版本已签名)
#   WinDivert64.sys (64位版本)

# 可选: 使用 winpcap-clone crate 或直接手写FFI
```

### 6.12 与现有模块集成

```
src/divert/capture.rs:
  - 查询 src/capture/event_loop.rs 维护的ETW连接表
  - 或通过共享的 ConnectionTracker (src/tracker.rs) 查询PID

src/divert/packet.rs:
  - 复用 src/parser/ndis.rs 的包解析逻辑
  - 复用 src/parser/dpi.rs 的DPI分析

src/output/:
  - 复用现有NDJSON输出格式
  - 新增 DivertPacketLine 类型 (可选)
```

### 6.13 注意事项

```
⚠️ unsafe_code = "forbid" 在当前Cargo.toml中

WinDivert FFI需要unsafe。解决方案:
  1. 将WinDivert模块放在独立crate中 (etwarden-divert)
     主crate禁止unsafe，子crate允许
  2. 或修改Cargo.toml: unsafe_code = "deny" (允许但警告)
  3. 最小化unsafe范围: 仅FFI调用处，其余逻辑全部safe

推荐方案1: 独立crate
  workspace/
    etwarden/          (unsafe_code = "forbid")
    etwarden-divert/   (允许unsafe, 仅WinDivert FFI)
```

---

## 7. Phase 4: 高级分析

### 7.1 Protobuf 解析

**来源**: `backend/PbSchema.go` (495行) + `backend/PbToJson.go`

**目标文件**: `src/parser/protobuf.rs` (新建)

```
功能:
  1. 导入 .proto 文件 → 编译为 FileDescriptor
  2. 导入 .descriptor 文件 (编译后的FileDescriptorSet)
  3. 指定 message type + skip字节数 → 二进制protobuf转JSON

Rust crates:
  prost       — Protobuf运行时
  prost-types — Well-known types
  prost-build — 编译.proto文件 (build.rs)

API:
  fn import_proto_schema(path: &Path) -> Result<Vec<String>>  // 返回可用message类型
  fn protobuf_to_json(data: &[u8], skip: usize, message_type: &str) -> Result<String>
```

### 7.2 全流量搜索

**来源**: `backend/Find.go` (771行)

**目标文件**: `src/search/mod.rs` (新建)

```rust
pub enum SearchType {
    Utf8,
    Gbk,
    Hex,
    Base64,
    Protobuf { skip: usize, message_type: String },
    Int32,
    Int64,
    Float32,
    Float64,
}

pub struct SearchResult {
    pub request_id: u64,
    pub offset: usize,
    pub length: usize,
    pub context: Vec<u8>,  // 匹配位置前后各64字节
}

pub fn search_all(requests: &[CapturedRequest], query: &str, search_type: SearchType, case_sensitive: bool) -> Vec<SearchResult>;
```

### 7.3 脚本引擎

**来源**: `backend/Config.go` (yaegi Go解释器)

**目标文件**: `src/script/mod.rs` (新建)

```
SunnyNet使用yaegi(Go解释器)，允许运行时修改流量。
Rust替代方案:

方案A: Lua脚本 (推荐)
  crate: mlua (Lua 5.4绑定)
  优点: 轻量、快速、安全(sandbox)
  回调: on_http_request(req) → 修改method/url/header/body
        on_http_response(req, resp) → 修改status/header/body
        on_tcp_data(data, direction) → 修改data
        on_websocket_frame(frame, direction) → 修改frame

方案B: WASM
  crate: wasmtime
  优点: 沙箱安全、多语言支持
  缺点: 编译流程复杂

方案C: Rhai (Rust原生脚本)
  crate: rhai
  优点: 无外部依赖、Rust风格语法
  缺点: 生态较小
```

Lua脚本示例:
```lua
-- etwarden-script.lua
function on_http_request(req)
    if req.url:find("ads%.example%.com") then
        req.drop = true
        return
    end
    req.headers["X-Etwarden"] = "captured"
end

function on_http_response(req, resp)
    if resp.headers["Content-Type"] and
       resp.headers["Content-Type"]:find("text/html") then
        resp.body = resp.body:gsub("</head>", "<!-- etwarden --></head>")
    end
end
```

### 7.4 请求代码生成

**来源**: `backend/CreateRequestCode.go`

**目标文件**: `src/codegen/mod.rs` (新建)

```
将捕获的HTTP请求转换为可执行代码:

支持语言:
  - Python (requests库)
  - JavaScript (fetch API)
  - Java (HttpURLConnection)
  - C# (HttpClient)
  - cURL命令
  - Rust (reqwest)

输入: CapturedRequest (method, url, headers, body)
输出: 代码字符串
```

---

## 8. 新增文件清单

### Phase 1

| 文件 | 类型 | 行数估计 | 说明 |
|------|------|---------|------|
| `src/parser/dpi/tls/fingerprint.rs` | 新建 | ~350 | TLS Client Hello解析 + JA3/JA4 |
| `src/parser/dpi/http.rs` | 新建 | ~200 | 明文HTTP DPI |
| `src/process/tree.rs` | 新建 | ~150 | 进程树关联 |

### Phase 2

| 文件 | 类型 | 行数估计 | 说明 |
|------|------|---------|------|
| `src/mitm/mod.rs` | 新建 | ~50 | MITM proxy模块入口 |
| `src/mitm/server.rs` | 新建 | ~400 | tokio异步proxy服务器 |
| `src/mitm/ca.rs` | 新建 | ~200 | rcgen证书管理 |
| `src/mitm/body.rs` | 新建 | ~150 | gzip/br/deflate解码 |
| `src/mitm/system_proxy.rs` | 新建 | ~100 | 系统代理设置 |

### Phase 3

| 文件 | 类型 | 行数估计 | 说明 |
|------|------|---------|------|
| `src/rules/mod.rs` | 新建 | ~30 | 规则引擎模块入口 |
| `src/rules/replace.rs` | 新建 | ~250 | 替换规则 |
| `src/rules/intercept.rs` | 新建 | ~200 | 拦截/断点规则 |
| `src/rules/hosts.rs` | 新建 | ~80 | Hosts重定向 |
| `src/rules/block.rs` | 新建 | ~300 | HTTP/WS/TCP/UDP屏蔽 |
| `src/rules/config.rs` | 新建 | ~150 | 规则配置加载/保存 |
| `src/replay/mod.rs` | 新建 | ~50 | 重放模块入口 |
| `src/replay/http.rs` | 新建 | ~200 | HTTP请求重放 |
| `src/replay/tcp.rs` | 新建 | ~100 | TCP/UDP重放 |

### Phase 4

| 文件 | 类型 | 行数估计 | 说明 |
|------|------|---------|------|
| `src/parser/protobuf.rs` | 新建 | ~200 | Protobuf解析 |
| `src/search/mod.rs` | 新建 | ~300 | 全流量搜索 |
| `src/script/mod.rs` | 新建 | ~50 | 脚本引擎入口 |
| `src/script/lua_engine.rs` | 新建 | ~300 | Lua脚本引擎 |
| `src/codegen/mod.rs` | 新建 | ~50 | 代码生成入口 |
| `src/codegen/python.rs` | 新建 | ~80 | Python代码生成 |
| `src/codegen/javascript.rs` | 新建 | ~80 | JavaScript代码生成 |
| `src/codegen/curl.rs` | 新建 | ~60 | cURL命令生成 |

---

## 9. 新增依赖清单

### Phase 1

```toml
[dependencies]
md-5 = "0.10"       # JA3 MD5计算
sha2 = "0.10"        # JA4 SHA-256计算
hex = "0.4"          # hex编解码 (可能已有)
```

### Phase 2

```toml
[dependencies]
rustls-mitm = "0.1"  # → 实际使用 http-mitm-proxy 0.18
tokio = { version = "1", features = ["full"] }
httparse = "1.9"     # HTTP/1.1解析
h2 = "0.4"           # HTTP/2
flate2 = "1.0"       # gzip/deflate解压
brotli = "7"         # brotli解压
rcgen = "0.13"       # 证书生成 (可能rustls-mitm已包含)
```

### Phase 3

```toml
[dependencies]
serde_json = "1"     # 规则配置JSON (可能已有)
regex = "1"          # 正则匹配 (可能已有)
reqwest = { version = "0.12", features = ["blocking"] }  # HTTP重放
```

### Phase 4

```toml
[dependencies]
prost = "0.13"           # Protobuf运行时
prost-types = "0.13"     # Protobuf well-known types
mlua = { version = "0.10", features = ["lua54", "vendored"] }  # Lua脚本
```

---

## 10. NDJSON 输出格式扩展

### 9.1 TLS 指纹事件

```json
{
  "type": "tls_hello",
  "ts": "2026-01-15T10:30:00.123Z",
  "pid": 1234,
  "process": "chrome.exe",
  "src": "192.168.1.100:54321",
  "dst": "93.184.216.34:443",
  "sni": "example.com",
  "alpn": ["h2", "http/1.1"],
  "tls_version": "TLS 1.3",
  "ja3": "771,4865-4866-4867...,0-23-65281...,29-23-24...,0",
  "ja3_hash": "a0e1f2d3c4b5a6e7f8d9c0b1a2e3f4d5",
  "ja4": "t13d1515h2_8daaf6152771_e5627efa2ab1",
  "cipher_count": 15,
  "ext_count": 15
}
```

### 9.2 HTTP 内容事件 (解密后)

```json
{
  "type": "http_request",
  "ts": "2026-01-15T10:30:00.456Z",
  "pid": 1234,
  "process": "chrome.exe",
  "method": "GET",
  "url": "https://example.com/api/data",
  "host": "example.com",
  "headers": {"User-Agent": "...", "Accept": "..."},
  "body_size": 0,
  "body_preview": null
}
```

```json
{
  "type": "http_response",
  "ts": "2026-01-15T10:30:00.789Z",
  "pid": 1234,
  "process": "chrome.exe",
  "status": 200,
  "content_type": "application/json",
  "content_encoding": null,
  "headers": {"Content-Type": "application/json"},
  "body_size": 1234,
  "body_preview": "{\"key\":\"value\"}..."
}
```

### 9.3 规则命中事件

```json
{
  "type": "rule_hit",
  "ts": "2026-01-15T10:30:00.123Z",
  "rule_type": "block",
  "rule_name": "Block Ads",
  "action": "CloseRequest",
  "direction": "upstream",
  "url": "https://ads.example.com/banner.js",
  "pid": 1234
}
```

---

## 11. 完成后能力对比

| 能力 | SunnyNet-wpf | etwarden 完成后 | 优势方 |
|------|-------------|----------------|--------|
| WinDivert非代理捕获 | 无 | WinDivert+ETW精确PID过滤 | **etwarden** |
| 进程关联 | nfapi端口匹配 | ETW精确PID | **etwarden** |
| HTTPS解密 | 魔改Go TLS | rustls-mitm | 平手 |
| TLS指纹 | JA3/JA4 | JA3/JA3N/JA4 | **etwarden** |
| DNS监控 | 无 | ETW DNS Client | **etwarden** |
| 被动情报 | 无 | 全量ETW元数据 | **etwarden** |
| 流量修改 | 有 | 有 | 平手 |
| 拦截断点 | 有 | 有 | 平手 |
| Protobuf | 有 | 有 | 平手 |
| 全流量搜索 | 有 | 有 | 平手 |
| 脚本引擎 | Go(yaegi) | Lua(mlua) | 平手 |
| 请求重放 | 有 | 有 | 平手 |
| 请求代码生成 | 有 | 有 | 平手 |
| 内容解码 | gzip/br/deflate | gzip/br/deflate | 平手 |
| 性能 | Go GC | Rust零成本 | **etwarden** |
| 部署 | 需装驱动 | 可纯用户态 | **etwarden** |
| 输出格式 | GUI绑定 | NDJSON管道 | **etwarden** |
| Hosts重定向 | 有 | 有 | 平手 |
| GUI | WPF | CLI(未来可加TUI) | SunnyNet |
| 跨平台 | Win/Linux/Mac | Win only | SunnyNet |

**etwarden 胜出项: 7 | 平手: 11 | SunnyNet胜出: 2**

---

## 12. 实施优先级总结

```
立即开始 (投入产出比最高):
  1. TLS SNI + JA3/JA4 指纹 (Phase 1, ~350行, 零新依赖)
  2. HTTP明文DPI (Phase 1, ~200行, 零新依赖)

第二批 (核心差异化):
  3. MITM proxy + HTTPS解密 (Phase 2, ~900行, 需新依赖)
  4. 内容解码 (Phase 2, ~150行)

第三批 (功能对齐):
  5. 替换规则引擎 (Phase 3, ~550行)
  6. 拦截/屏蔽规则 (Phase 3, ~500行)
  7. 请求重放 (Phase 3, ~350行)

第三批半 (非代理流量捕获):
  8. WinDivert FFI绑定 (Phase 3.5, ~250行, 需独立crate)
  9. WinDivert捕获循环+PID过滤 (Phase 3.5, ~650行)

第四批 (锦上添花):
  10. Protobuf解析 (Phase 4, ~200行)
  11. 全流量搜索 (Phase 4, ~300行)
  12. Lua脚本引擎 (Phase 4, ~300行)
  13. 请求代码生成 (Phase 4, ~270行)
```
