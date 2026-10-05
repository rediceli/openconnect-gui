//! openconnect 日志 → 结构化状态事件 + 状态机
//!
//! 输入: `openconnect -v --timestamp` 的 stdout+stderr 合并流
//! 输出: [`Event`]，供 UI 状态机消费
//!
//! # 规则表的来源
//!
//! 每条 pattern 都能在 openconnect 源码里 grep 到（文件:行 已注明）。
//! 这不是可选的严谨性 —— openconnect 的日志文案就是它的 UI 契约。
//!
//! ⚠️ **不要基于网络资料/博客/社区文档写这张表。** P0 阶段的教训：
//! 下列常见字符串在 openconnect 源码中**根本不存在**：
//! `Established session to`、`Assigned IP address`、`Data connection: `、
//! `DPD data channel`、`Reconnect interval`、`Please try again`。
//! 照抄文档会得到一个"能跑但永远连不上"的客户端。
//!
//! 新增规则前请先跑：
//! ```sh
//! grep -rn "<pattern>" openconnect-master/*.c
//! ```

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    /// openconnect 直接 fprintf 到终端的交互提示（非 vpn_progress）
    Prompt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// 未识别的普通日志行
    Log,
    /// 开始连接
    Connecting,
    /// TLS 握手完成
    TlsEstablished,
    /// 需要用户交互（表单、令牌、指纹确认）
    Prompt,
    /// 认证失败（密码错、账号锁、证书被拒、分组不存在）
    AuthFailed,
    /// 认证已通过，开始建立 CSTP 隧道通道
    TunnelStarting,
    /// 会话建立，拿到分配的 IP
    SessionEstablished,
    /// 隧道数据通道已建立，TUN 已 up
    TunnelUp,
    /// 隧道断开
    TunnelDown,
    /// 周期性统计（隧道健康信号）
    Stats,
    /// 服务端要求重连
    Reconnect,
    /// 收到终止信号 / 用户取消（正常断开）
    Signalled,
    /// 致命错误，进程即将退出
    Fatal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts: Option<String>,
    pub level: Level,
    pub kind: Kind,
    /// 事件相关字段，如 ciphersuite / address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// 原始行，日志页原样展示
    pub raw: String,
}

// ---------------------------------------------------------------------------
// 时间戳剥离
// ---------------------------------------------------------------------------

/// 拆分 `--timestamp` 前缀 `[YYYY-MM-DD HH:MM:SS] `。
/// openconnect 用固定格式生成，形状不变，手写校验比正则更轻。
fn strip_timestamp(line: &str) -> (Option<&str>, &str) {
    const TS_LEN: usize = 19; // YYYY-MM-DD HH:MM:SS
    let b = line.as_bytes();
    // '[' + 19 + ']' + ' '
    if b.len() > TS_LEN + 3 && b[0] == b'[' && b[TS_LEN + 1] == b']' && b[TS_LEN + 2] == b' '
    {
        let ok = b[1..=TS_LEN].iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b' ',
            13 | 16 => *c == b':',
            _ => c.is_ascii_digit(),
        });
        if ok {
            return (Some(&line[1..=TS_LEN]), line[TS_LEN + 3..].trim_start());
        }
    }
    (None, line)
}

// ---------------------------------------------------------------------------
// 事件判定表。顺序即优先级，越具体越靠前。
// ---------------------------------------------------------------------------

type Rule = (&'static str, Level, Kind, Option<&'static str>);

const RULES: &[Rule] = &[
    // ---- 连接建立 ----
    ("Attempting to connect to server", Level::Debug, Kind::Connecting, None), // ssl.c
    ("Failed to connect to", Level::Error, Kind::Fatal, None),                  // ssl.c
    ("Connected to HTTPS on", Level::Info, Kind::TlsEstablished, Some("ciphersuite")), // gnutls.c/openssl.c
    ("Failed to open HTTPS connection", Level::Error, Kind::Fatal, None),       // auth.c

    // ---- 交互提示 ----
    ("GROUP:", Level::Prompt, Kind::Prompt, None),                              // main.c 分组下拉
    ("Please enter your username and password", Level::Prompt, Kind::Prompt, None),
    ("Password:", Level::Prompt, Kind::Prompt, None),                          // auth.c/fortinet.c/pulse.c
    ("PIN:", Level::Prompt, Kind::Prompt, None),                               // stoken.c 软令牌 PIN
    ("Enter software token PIN", Level::Prompt, Kind::Prompt, None),           // stoken.c
    ("Token code request", Level::Prompt, Kind::Prompt, None),                 // pulse.c
    ("Invalid PIN format", Level::Warn, Kind::Prompt, None),                   // stoken.c
    ("Server certificate", Level::Prompt, Kind::Prompt, None),                  // main.c 指纹确认
    // ⚠️ 认证表单是**阻塞式**的：openconnect 会 fprintf 提示后等 stdin。
    //    GUI 客户端必须用 -F / --passwd-on-stdin 预填，否则连接会卡死。
    ("User input required in non-interactive mode", Level::Error, Kind::AuthFailed, None), // main.c prompt_for_input

    // ---- 认证失败 ----
    ("Certificate Validation Failure", Level::Error, Kind::AuthFailed, None),   // auth.c
    ("Client certificate missing or incorrect", Level::Error, Kind::AuthFailed, None), // auth.c 改写后文案
    ("consecutive empty forms", Level::Error, Kind::AuthFailed, None),         // main.c
    ("Auth choice \"", Level::Error, Kind::AuthFailed, None),                   // main.c 分组值不存在
    ("matches multiple options", Level::Error, Kind::AuthFailed, None),        // main.c 分组值有歧义
    ("Failed to complete authentication", Level::Error, Kind::AuthFailed, None), // main.c

    // ---- 隧道 ----
    // main.c:1663 print_connection_info()
    //   "Configured as %s, with SSL + ... %s and UDP + ... %s"
    ("Configured as", Level::Info, Kind::SessionEstablished, Some("address")),
    ("Got CONNECT response", Level::Info, Kind::TunnelStarting, None),        // cstp.c
    ("CSTP connected", Level::Info, Kind::TunnelUp, None),                     // cstp.c
    ("Set up tun script failed", Level::Error, Kind::Fatal, None),             // mainloop.c
    ("Set up tun device failed", Level::Error, Kind::Fatal, None),             // mainloop.c
    ("No --script argument provided", Level::Warn, Kind::Log, None),           // main.c

    // ---- 统计（周期性，说明隧道已 up）----
    ("RX:", Level::Info, Kind::Stats, None),                                    // main.c print_connection_stats
    ("Session authentication will expire at", Level::Info, Kind::Stats, None),
    ("Next SSL rekey in", Level::Info, Kind::Stats, None),
    ("Next UDP rekey in", Level::Info, Kind::Stats, None),
    ("SSL ciphersuite:", Level::Info, Kind::Stats, None),

    // ---- 重连 / 会话终止 ----
    ("User requested reconnect", Level::Info, Kind::Reconnect, None),           // main.c
    ("Cookie was rejected by server", Level::Error, Kind::Fatal, None),         // main.c cookie 过期
    ("Session terminated by server", Level::Error, Kind::Fatal, None),          // main.c

    // ---- 终止 ----
    ("User cancelled", Level::Info, Kind::Signalled, None),                     // main.c
    ("User detached from session", Level::Info, Kind::Signalled, None),         // main.c
    ("Unrecoverable I/O error", Level::Error, Kind::Fatal, None),               // main.c
    ("Got inappropriate HTTP CONNECT response", Level::Error, Kind::Fatal, None),
    ("Failed to establish VPN connection", Level::Error, Kind::Fatal, None),
    ("Unknown error; exiting", Level::Error, Kind::Fatal, None),                // main.c
    ("; exiting", Level::Error, Kind::Fatal, None),                             // main.c 兜底 "%s; exiting"
];

pub fn parse_line(raw: &str) -> Option<Event> {
    let line = raw.trim_end_matches(['\r', '\n']);
    if line.trim().is_empty() {
        return None;
    }
    let (ts, body) = strip_timestamp(line);

    for (pat, level, kind, field) in RULES {
        if !body.contains(pat) {
            continue;
        }
        let detail = field.and_then(|f| extract_field(body, f));
        return Some(Event {
            ts: ts.map(str::to_owned),
            level: *level,
            kind: *kind,
            detail,
            raw: line.to_owned(),
        });
    }

    Some(Event {
        ts: ts.map(str::to_owned),
        level: Level::Info,
        kind: Kind::Log,
        detail: None,
        raw: line.to_owned(),
    })
}

/// 提取事件的附加字段。
fn extract_field(body: &str, field: &str) -> Option<String> {
    match field {
        // "Connected to HTTPS on HOST with ciphersuite (TLS1.3)-(...)"
        "ciphersuite" => body
            .rsplit_once("ciphersuite ")
            .map(|(_, v)| v.trim().to_owned()),
        // "Configured as 10.0.0.2/255.255.255.0, with SSL ..."
        "address" => body
            .strip_prefix("Configured as ")
            .map(|v| {
                v.split(", with ")
                    .next()
                    .unwrap_or(v)
                    .trim()
                    .to_owned()
            }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// 状态机
// ---------------------------------------------------------------------------

/// 对 UI 暴露的连接状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// 进程未启动 / 已退出
    #[default]
    Idle,
    /// TCP + TLS 握手中
    Connecting,
    /// 等待用户输入（表单、令牌、指纹确认）
    AwaitingUser,
    /// 已提交凭据，等待服务器判定
    Authenticating,
    /// 认证已通过，正在建立 CSTP 隧道通道
    Configuring,
    /// 隧道数据通道已建立，TUN 已 up
    Connected,
    /// openconnect 正在自动重连
    Reconnecting,
    /// 因错误终止
    Failed,
}

/// 终止原因。
///
/// P0 发现：认证成功与认证失败在 [`State`] 上都终结于 `Failed`，无法区分。
/// 而这两者的 UI 行为截然不同：
/// - 认证失败 → 弹出密码框，改密码后重连
/// - 隧道建立失败 → 提示换网关 / 调 MTU / 换协议
///
/// 因此必须单独记录，由末尾若干条 `Event::kind` 推导。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TerminalCause {
    /// 凭据被拒：密码错误、账号锁定、证书不被接受
    AuthRejected { reason: String },
    /// 分组/realm 下拉值在服务器上不存在或有歧义
    AuthGroupInvalid { reason: String },
    /// 认证表单需要交互，但没被预填（`-F` / `--passwd-on-stdin` 缺失或写错）
    ///
    /// 这是最容易踩的一类：GUI 里表现为「连接一直转圈，无错误提示」。
    UserInputRequired { prompt: String },
    /// 服务器不可达 / TLS 失败
    NetworkUnreachable { reason: String },
    /// 服务器证书校验失败
    CertificateRejected { reason: String },
    /// 认证通过但隧道建立失败（CONNECT / DTLS / vpnc-script）
    TunnelSetupFailed { reason: String },
    /// 会话被服务端终止（cookie 过期等）
    SessionTerminated { reason: String },
    /// 未分类的进程退出
    Unknown { reason: String },
    /// 用户主动断开，非错误
    UserCancelled,
    /// 需要管理员权限才能建立隧道。
    ///
    /// 单独一类是因为它的解法不是「重试」而是「先启动特权助手」，
    /// UI 必须引导用户做点不同的事。
    PrivilegeRequired {
        /// 面向用户的操作提示（如具体的 pkexec 命令）
        hint: String,
    },
}

impl TerminalCause {
    /// 是否值得让用户重试（vs. 提示改配置）
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            TerminalCause::AuthRejected { .. } | TerminalCause::NetworkUnreachable { .. }
        )
    }

    /// i18n key
    pub fn message_key(&self) -> &'static str {
        match self {
            TerminalCause::AuthRejected { .. } => "error.auth_rejected",
            TerminalCause::AuthGroupInvalid { .. } => "error.auth_group_invalid",
            TerminalCause::UserInputRequired { .. } => "error.user_input_required",
            TerminalCause::NetworkUnreachable { .. } => "error.network_unreachable",
            TerminalCause::CertificateRejected { .. } => "error.cert_rejected",
            TerminalCause::TunnelSetupFailed { .. } => "error.tunnel_setup_failed",
            TerminalCause::SessionTerminated { .. } => "error.session_terminated",
            TerminalCause::Unknown { .. } => "error.unknown",
            TerminalCause::UserCancelled => "error.user_cancelled",
            TerminalCause::PrivilegeRequired { .. } => "error.privilege_required",
        }
    }
}

/// 状态机。把逐行事件聚合成状态与终止原因。
///
/// 认证成功的判定**不能**依赖日志文案 —— openconnect 在
/// `<auth id="success">` 路径下不打任何日志（P0 实测）。因此采用
/// 「请求计数 + Set-Cookie + CONNECT 响应」组合推断。
#[derive(Debug, Default)]
pub struct Tracker {
    state: State,
    /// 已提交凭据
    submitted: bool,
    /// 提交后是否收到 cookie（仅诊断用，**不作判据** ——
    /// 网关在认证失败时同样下发 Set-Cookie）
    cookie_seen: bool,
    /// 已打印 "Attempting to connect to server"（首个 POST 在此之前）
    saw_attempt: bool,
    /// 最近的若干条事件，用于推导 TerminalCause
    recent: std::collections::VecDeque<Kind>,
    /// 最近的失败原因原文（可能多条），按时间顺序。
    /// 不能只留最后一条 —— openconnect 的收尾是
    /// 「具体原因 → ; exiting → Unknown error; exiting.」，
    /// 最后一条永远是 "Unknown error"，会把真正的原因冲掉。
    failure_reasons: std::collections::VecDeque<String>,
    /// 最近一次 Prompt 的原文
    last_prompt: Option<String>,
    /// 已进入终态（正常或异常），不再重复 emit
    terminated: bool,
    /// 已进入终态失败，后续事件不再改变状态。
    ///
    /// openconnect 在部分失败后会继续走流程（例如分组值无效时
    /// `match_choice_label` 返回 -EINVAL → 转去弹交互式下拉）。
    /// 若不锁存，UI 会从「认证失败」被拉回「等待输入」，
    /// 用户看到一个永远转圈的连接界面。
    latched_failure: bool,
}

/// 保留多少条最近事件/失败原因用于推导。
/// 需覆盖「具体原因 → ; exiting → Unknown error; exiting.」这种收尾组合。
const RECENT_CAP: usize = 8;

impl Tracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn cause(&self) -> Option<TerminalCause> {
        self.derive_cause()
    }

    fn to(&mut self, next: State) -> Option<(State, State)> {
        if self.state == next {
            return None;
        }
        let prev = std::mem::replace(&mut self.state, next);
        Some((prev, next))
    }

    /// 正常断开同样只 emit 一次。
    fn settle_idle(&mut self) -> Option<(State, State)> {
        if self.terminated {
            return None;
        }
        self.terminated = true;
        self.to(State::Idle)
    }

    /// 终态收敛。
    ///
    /// openconnect 在失败时会连打多条错误日志（具体原因 → `; exiting` →
    /// `Unknown error; exiting.`），每条都会被分类成 Fatal。若直接透传，
    /// UI 会收到 3 次 Failed 事件。这里只在**首次进入**终态时返回变化，
    /// 之后的原因记录仍继续累积（供 derive_cause 取最具体的那条）。
    fn settle(&mut self, next: State) -> Option<(State, State)> {
        if self.terminated {
            return None;
        }
        self.terminated = true;
        self.to(next)
    }

    /// 喂入一行原始日志。
    pub fn feed_line(&mut self, raw: &str) -> Option<(State, State)> {
        let ev = parse_line(raw)?;
        self.feed(ev)
    }

    pub fn feed(&mut self, ev: Event) -> Option<(State, State)> {
        // 「Attempting to connect」之后的第一条 POST 才是凭据提交；
        // 在此之前的 POST 是 XML 初始请求，不代表用户已提交。
        let is_request = ev.raw.contains("] POST ") || ev.raw.starts_with("POST ");
        if ev.raw.starts_with("Set-Cookie:") || ev.raw.contains("] Set-Cookie:") {
            self.cookie_seen = true;
        }

        self.recent.push_back(ev.kind);
        while self.recent.len() > RECENT_CAP {
            self.recent.pop_front();
        }
        if matches!(ev.kind, Kind::Fatal | Kind::AuthFailed) {
            self.failure_reasons.push_back(ev.raw.clone());
            while self.failure_reasons.len() > RECENT_CAP {
                self.failure_reasons.pop_front();
            }
            self.latched_failure = true;
        }

        match ev.kind {
            Kind::Connecting => {
                self.saw_attempt = true;
                self.to(State::Connecting)
            }
            Kind::Prompt => {
                self.last_prompt = Some(ev.raw.clone());
                // 隧道已建立后的提示（重连等）不应把 UI 拉回「等待输入」
                if self.state == State::Connected || self.state == State::Reconnecting {
                    return None;
                }
                // 已锁存的失败不会被后续交互提示覆盖
                if self.latched_failure {
                    return None;
                }
                // 新一轮表单 ⇒ 上一轮的提交状态作废
                self.submitted = false;
                self.cookie_seen = false;
                self.to(State::AwaitingUser)
            }
            Kind::TlsEstablished => None,
            Kind::AuthFailed => self.settle(State::Failed),
            Kind::TunnelStarting => {
                self.submitted = true;
                self.to(State::Configuring)
            }
            Kind::SessionEstablished | Kind::TunnelUp => {
                self.submitted = true;
                self.to(State::Connected)
            }
            Kind::TunnelDown => self.to(State::Idle),
            Kind::Reconnect => self.to(State::Reconnecting),
            Kind::Signalled => self.settle_idle(),
            Kind::Stats => {
                // 统计行只在隧道 up 后出现，用于兜底确认 Connected
                if self.state == State::Configuring {
                    self.to(State::Connected)
                } else {
                    None
                }
            }
            Kind::Fatal => self.settle(State::Failed),
            Kind::Log => {
                if is_request && self.saw_attempt && !self.submitted {
                    self.submitted = true;
                    return self.to(State::Authenticating);
                }
                None
            }
        }
    }

    /// 子进程退出时的最终裁决。
    pub fn on_exit(&mut self, code: Option<i32>) -> Option<(State, State)> {
        if self.state == State::Connected {
            return self.to(State::Idle);
        }
        match code {
            Some(0) => self.to(State::Idle),
            _ => self.to(State::Failed),
        }
    }

    /// 由最近事件推导终止原因。
    ///
    /// 判定顺序 = 具体性从高到低。收尾的 "Unknown error; exiting."
    /// 永远匹配不到任何具体规则，会落到 Unknown 兜底 ——
    /// 所以必须在**多条**原因里找最具体的那条，而不是只看最后一条。
    pub fn derive_cause(&self) -> Option<TerminalCause> {
        let reasons: Vec<&str> = self.failure_reasons.iter().map(|s| s.as_str()).collect();
        let all = reasons.join(" | ");

        let find = |pat: &str| reasons.iter().find(|r| r.contains(pat)).copied();

        // ---- 认证阶段 ----
        if let Some(r) = find("Auth choice").or_else(|| find("matches multiple options")) {
            return Some(TerminalCause::AuthGroupInvalid { reason: r.into() });
        }
        if self.recent.contains(&Kind::AuthFailed) {
            if let Some(r) = find("Certificate").or_else(|| find("certificate")) {
                return Some(TerminalCause::AuthRejected { reason: r.into() });
            }
            if let Some(r) = find("Failed to complete authentication") {
                return Some(TerminalCause::AuthRejected { reason: r.into() });
            }
            // 分组/realm 值存在但服务端不接受，仍归认证拒绝
            if let Some(r) = reasons.first() {
                return Some(TerminalCause::AuthRejected { reason: (*r).into() });
            }
        }

        // ---- 证书校验 ----
        if let Some(r) = find("Certificate Validation Failure") {
            return Some(TerminalCause::CertificateRejected { reason: r.into() });
        }

        // ---- 会话终止 ----
        if let Some(r) = find("Cookie was rejected").or_else(|| find("Session terminated")) {
            return Some(TerminalCause::SessionTerminated { reason: r.into() });
        }

        // ---- 隧道建立 ----
        if let Some(r) = find("CONNECT")
            .or_else(|| find("tun device"))
            .or_else(|| find("tun script"))
            .or_else(|| find("DTLS"))
            .or_else(|| find("dtls"))
        {
            return Some(TerminalCause::TunnelSetupFailed { reason: r.into() });
        }

        // ---- 网络 ----
        if let Some(r) = find("Failed to connect to")
            .or_else(|| find("Failed to open HTTPS"))
            .or_else(|| find("I/O error"))
        {
            return Some(TerminalCause::NetworkUnreachable { reason: r.into() });
        }

        // ---- 交互式表单未被预填 ----
        // 必须在上面所有失败分类之后判断：openconnect 失败后常会
        // 继续弹交互提示，若优先判 UserInputRequired 会误导用户。
        if self.state == State::AwaitingUser {
            return Some(TerminalCause::UserInputRequired {
                prompt: self.last_prompt.clone().unwrap_or_default(),
            });
        }

        if self.state == State::Idle {
            return Some(TerminalCause::UserCancelled);
        }
        // 非零退出但一条原因都没归类出来时，**必须**给出点什么。
        //
        // 没有这条兜底，GUI 会收到 Failed 状态却收不到任何 CAUSE，
        // 提示就永远停在「正在连接…」—— 用户既不知道失败了，也
        // 不知道原因（实测：密码留空时 openconnect 的
        // "fgets (stdin): Inappropriate ioctl for device" 就属于这一类，
        // 它既不是认证失败也不是网络问题）。
        if self.state == State::Failed {
            return Some(TerminalCause::Unknown { reason: all });
        }
        if !all.is_empty() {
            return Some(TerminalCause::Unknown { reason: all });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(line: &str) -> Event {
        parse_line(line).expect("not empty")
    }

    #[test]
    fn strips_timestamp() {
        let e = one("[2026-10-03 02:09:40] XML POST enabled");
        assert_eq!(e.ts.as_deref(), Some("2026-10-03 02:09:40"));
        assert_eq!(e.kind, Kind::Log);
    }

    #[test]
    fn line_without_timestamp_is_prompt() {
        let e = one("Please enter your username and password.");
        assert_eq!(e.ts, None);
        assert_eq!(e.kind, Kind::Prompt);
        assert_eq!(e.level, Level::Prompt);
    }

    #[test]
    fn tls_ciphersuite_extracted() {
        let e = one("[2026-10-03 02:09:40] Connected to HTTPS on vpn.corp with ciphersuite (TLS1.3)-(ECDHE-X25519)-(AES-256-GCM)");
        assert_eq!(e.kind, Kind::TlsEstablished);
        assert_eq!(
            e.detail.as_deref(),
            Some("(TLS1.3)-(ECDHE-X25519)-(AES-256-GCM)")
        );
    }

    #[test]
    fn configured_as_extracts_assigned_address() {
        let e = one("[2026-10-03 02:09:40] Configured as 10.99.99.2/255.255.255.0, with SSL + deflate-ipv6 AES-256-GCM and UDP + AES-256-GCM ikev2");
        assert_eq!(e.kind, Kind::SessionEstablished);
        assert_eq!(e.detail.as_deref(), Some("10.99.99.2/255.255.255.0"));
    }

    #[test]
    fn group_prompt_recognised() {
        assert_eq!(one("GROUP: [|Engineering|Operations]:").kind, Kind::Prompt);
    }

    #[test]
    fn bad_group_value_is_auth_failed() {
        // main.c:2704
        let e = one("[2026-10-03 02:09:40] Auth choice \"Nonexistent\" not available");
        assert_eq!(e.kind, Kind::AuthFailed);
    }

    #[test]
    fn non_interactive_required_is_auth_failed() {
        // 这是 -F 字段名写错时最典型的症状
        let e = one("[2026-10-03 02:09:40] User input required in non-interactive mode");
        assert_eq!(e.kind, Kind::AuthFailed);
    }

    #[test]
    fn stats_line_recognised() {
        let e = one("[2026-10-03 02:10:00] RX: 1024 packets (65536 B); TX: 2048 packets (131072 B)");
        assert_eq!(e.kind, Kind::Stats);
    }

    #[test]
    fn quit_reason_kinds() {
        assert_eq!(one("Cookie was rejected by server; exiting.").kind, Kind::Fatal);
        assert_eq!(
            one("User cancelled (SIGINT/SIGTERM); exiting.").kind,
            Kind::Signalled
        );
    }

    #[test]
    fn blank_lines_skipped() {
        assert!(parse_line("   \n").is_none());
        assert!(parse_line("\n").is_none());
    }
}