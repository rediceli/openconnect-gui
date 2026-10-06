// Tauri API 的取法。
//
// ⚠️ **不要**写成 `await import("@tauri-apps/api/core")` —— 那是 npm
// 包的裸模块说明符。本项目没有构建链、没有 node_modules，浏览器无法
// 解析它，那一行会直接抛错并中止整个模块：界面看起来完好，但 JS 一行
// 都没执行（下拉框空、「检测中…」卡住、按钮点了没反应，且无任何报错）。
//
// 无构建链下的正确做法：`tauri.conf.json` 里设
// `app.withGlobalTauri = true`，然后用 `window.__TAURI__`。
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);
let profiles = [];
let current = null;

const STATE_LABEL = {
  idle:"未连接", connecting:"连接中", awaiting_user:"等待输入",
  authenticating:"验证身份", configuring:"建立隧道",
  connected:"已连接", reconnecting:"重连中", failed:"失败",
};

function tab(which) {
  for (const k of ["conn","prof","log","cfg"]) {
    $("v-"+k).classList.toggle("hide", k !== which);
    $("tab-"+k).classList.toggle("on", k === which);
  }
}

function msg(text, isErr) {
  const el = $("msg");
  el.textContent = text;
  el.className = "msg" + (isErr ? " err" : "");
}

// 「会话存在中」—— 这些状态下不能再次发起连接，否则会并发开第二条隧道。
// 注意 awaiting_user（等待证书确认/表单输入）也算：那时连接还没断。
const SESSION_ACTIVE = [
  "connecting", "awaiting_user", "authenticating", "configuring", "reconnecting",
];

// 上一个状态是否属于「会话进行中」，以及这一轮结束是否已由 CAUSE 解释过。
let wasActive = false;
let endedByCause = false;
// 用户主动点了「断开」——结束是预期内的，不要报成错误。
let userStopped = false;

// ---- 连接时长 ----
// 记下进入「已连接」的时刻，用 setInterval 自己走秒。
// 不用服务端时间戳：openconnect 那边没有可用的「连接起始时刻」，
// 而 GUI 进程一直活着，本地计时足够准。
let connectedAt = null;
let tickTimer = null;

// ---- 收发统计 ----
let lastStats = null;

function fmtDuration(ms) {
  const total = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const pad = (n) => String(n).padStart(2, "0");
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${pad(m)}:${pad(s)}`;
}

// 单位换算是显示决策，放在前端而不是后端：后端只给原始字节数。
function fmtBytes(n) {
  if (n == null) return "—";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i += 1; }
  return (i === 0 ? String(v) : v.toFixed(1)) + " " + u[i];
}

function renderStats() {
  const box = $("stats");
  const clock = $("stat-time");
  if (!box || !clock) return;
  const on = connectedAt !== null;
  // 时长与统计同进同退：断开后留着上一次的数字会让人以为还在连。
  box.classList.toggle("hide", !on);
  clock.classList.toggle("hide", !on);
  if (!on) return;
  clock.textContent = fmtDuration(Date.now() - connectedAt);
  const rx = $("stat-rx"), tx = $("stat-tx");
  if (lastStats) {
    rx.textContent = `${fmtBytes(lastStats.rxBytes)} / ${lastStats.rxPkts} 包`;
    tx.textContent = `${fmtBytes(lastStats.txBytes)} / ${lastStats.txPkts} 包`;
  } else {
    // openconnect 的第一行统计要等一个周期才来，先别显示 0 ——
    // 「0 B」会被误读成「流量真的是 0」。
    rx.textContent = "等待数据…";
    tx.textContent = "等待数据…";
  }
}

function startTimer() {
  if (tickTimer !== null) return;
  tickTimer = setInterval(renderStats, 1000);
}

function stopTimer() {
  if (tickTimer !== null) { clearInterval(tickTimer); tickTimer = null; }
}

function setState(s) {
  const pill = $("state");
  pill.textContent = STATE_LABEL[s] ?? s;
  pill.className = "pill s-" + s;

  const btn = $("go");
  const connected = s === "connected";
  const active = SESSION_ACTIVE.includes(s);

  // 已连接时按钮是「断开」，必须可点 —— 它是唯一的断开入口。
  // 其余有会话进行中的状态一律禁用，避免并发开第二条隧道。
  btn.textContent = connected ? "断开" : "连接";
  btn.disabled = active;
  btn.title = active ? "连接进行中，请先断开" : "";

  // 隧道「自己结束了」但没有给出原因（openconnect 非零退出、
  // 没走到任何可识别分支）时，CAUSE 事件不来，提示就会永远停在
  // 「正在连接…」，用户只看到状态跳回未连接却不知道发生了什么。
  // 这里兜一句底，指向日志页。
  //
  // 只认 idle：Finished/Failed 都自带 CAUSE，抢在它前面弹这句会闪一下。
  // 用户主动断开也不算异常 —— 那条路没有原因可解释。
  if (wasActive && s === "idle" && !endedByCause && !userStopped) {
    msg("连接已结束，详情见「日志」页", true);
  }
  if (s === "connected") msg("隧道已建立");
  if (s === "idle" && userStopped) msg("已断开");

  // 时长与统计只在「已连接」期间有意义。
  // 重连（reconnecting → connected）不重置：隧道还是同一条，
  // 用户视角里连接没断。
  if (s === "connected") {
    if (connectedAt === null) connectedAt = Date.now();
    startTimer();
  } else if (s === "idle" || s === "failed") {
    connectedAt = null;
    lastStats = null;
    stopTimer();
  }
  renderStats();

  wasActive = active;
  endedByCause = false;
  if (s === "idle") userStopped = false;
}

async function loadProfiles() {
  profiles = await invoke("list_profiles");
  const sel = $("profile");
  sel.innerHTML = "";
  if (!profiles.length) {
    sel.innerHTML = '<option value="">（新建连接）</option>';
  } else {
    for (const p of profiles) {
      const o = document.createElement("option");
      o.value = p.id;
      o.textContent = p.name + " — " + p.server;
      sel.appendChild(o);
    }
    if (!current) current = profiles[0].id;
  }
  sel.value = current ?? "";
  // ⚠️ 必须显式调render()。
  //
  // `sel.value = ...` 是**程序化赋值，不会触发 change 事件**，所以
  // 只靠 `$("profile").addEventListener("change", render)` 的话，
  // 启动时虽然下拉框已经选中了 profile，表单里的网关地址/用户名
  // 仍是空的 —— 用户看到「选了一个连接但什么字段都没填」。
  //
  // 而且必须放在 `if (!current) current = ...` 之后，否则 current
  // 为空时 render() 会拿不到 profile。
  render();
  renderList();
}

function render() {
  current = $("profile").value || null;
  const p = profiles.find(x => x.id === current);
  $("server").value   = p?.server ?? "";
  $("username").value = p?.username ?? "";
  $("remember").checked = !!p?.remember_password;
  $("password").value = "";
  if (p) {
    invoke("has_saved_password", { profile: p }).then(s => {
      $("password").placeholder = s ? "已保存在钥匙串" : "留空则每次询问";
    });
  }
  renderList();
}

function renderList() {
  const box = $("plist");
  box.innerHTML = "";
  for (const p of profiles) {
    const d = document.createElement("div");
    d.className = "prof" + (p.id === current ? " sel" : "");
    d.onclick = () => { current = p.id; $("profile").value = p.id; render(); };
    d.innerHTML = `<div><b>${esc(p.name)}</b><small>${esc(p.server)}</small></div>`;
    const x = document.createElement("button");
    x.className = "x"; x.textContent = "✕";
    x.onclick = async (e) => { e.stopPropagation();
      await invoke("delete_profile", { id: p.id }); await loadProfiles(); };
    d.appendChild(x);
    box.appendChild(d);
  }
}

const esc = (s) => String(s).replace(/[&<>"]/g, c =>
  ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;" }[c]));

async function saveProfile() {
  const server = $("server").value.trim();
  if (!server) return msg("请填写网关地址", true);
  const p = {
    id: current ?? (crypto.randomUUID()),
    name: server.split("/")[0],
    server,
    protocol: "anyconnect",
    username: $("username").value.trim() || null,
    remember_password: $("remember").checked,
  };
  const saved = await invoke("save_profile", { profile: p });
  current = saved.id;
  if ($("remember").checked && $("password").value) {
    await invoke("store_password", { profile: saved, password: $("password").value });
  }
  await loadProfiles();
  msg("已保存");
}

// ---- 文案表 ----
//
// Rust 侧只给出稳定的 key（如 `error.tunnel_setup_failed`），中文文案放前端。
// 之前直接把 key 显示给用户，看到的是「已结束：error.tunnel_setup_failed」
// —— 等于没有提示。
//
// 键名与 `src/` 下的 `message_key()` 一一对应；新增 key 时两边要同步，
// 漏了会 fallback 到「未知错误（key）」而不是静默空白。
const I18N = {
  "error.auth_rejected": "认证被拒绝：用户名、密码或证书不被接受",
  "error.auth_group_invalid": "认证分组无效：该分组在服务器上不存在或有歧义",
  "error.user_input_required": "服务器要求输入，但未预填：请检查用户名/分组设置",
  "error.network_unreachable": "无法连接服务器：检查网络或防火墙",
  "error.cert_rejected": "服务器证书校验失败",
  "error.tunnel_setup_failed": "隧道建立失败：可能需要管理员权限才能创建网络设备",
  "error.session_terminated": "会话被服务器终止：可能是凭据过期",
  "error.user_cancelled": "已取消",
  "error.privilege_required": "需要管理员权限：请先安装并启动特权助手",
  "error.unknown": "未知错误",

  "channel.error.key_leak": "拒绝启动：密钥会泄漏进命令行",
  "channel.error.rejected_args": "拒绝启动：连接参数包含被禁止的选项",
  "channel.error.openconnect_missing": "找不到 openconnect，请先安装",
  "channel.error.spawn_failed": "启动 openconnect 失败",
  "channel.error.macosctl_missing": "应用安装不完整：缺少 macosctl，请重新安装",
  "channel.error.macosctl_spawn_failed": "启动 macosctl 失败",

  "helper.status.ready": "特权助手已就绪",
  "helper.status.not_installed": "特权助手未安装",
  "helper.status.not_found": "特权助手未随应用安装，请重新安装 OC GUI",
  "helper.status.requires_approval": "请在「系统设置 → 通用 → 登录项」批准 OC GUI",
  "helper.status.need_elevation": "需要管理员权限才能建立 VPN 连接",
};

const t = (key, fallback) => I18N[key] ?? fallback ?? `未知错误（${key}）`;

// ---- 服务器证书首次信任（TOFU）----
//
// 未设pin 时 openconnect 会向已被 --passwd-on-stdin 占用的 stdin 索要
// 交互确认，用户永远看不到这个问题。因此我们先自己探测证书、让用户确认，
// 再把 pin 写进 profile。
function certDialog(info) {
  return new Promise((resolve) => {
    $("c-host").textContent = info.host + ":" + info.port;
    $("c-subject").textContent = info.subject || "(空)";
    $("c-issuer").textContent = info.issuer || "(空)";
    $("c-valid").textContent = info.notBefore + " → " + info.notAfter;
    $("c-fp").textContent = info.certSha256;
    $("c-pin").textContent = info.pinSha256;

    // 自签 + CN 是占位符是最常见的自签特征，风险最高，警告要最强。
    const warns = [];
    if (info.selfSigned) {
      warns.push("证书是<b>自签</b>的（主体与签发者相同），无法通过 CA 校验链验证。");
    }
    if (/yourhost|example\.com|localhost/i.test(info.subject)) {
      warns.push("证书主体是 <b>" + info.subject + "</b> —— 这是 ocserv/OpenWRT 的默认占位符，" +
                 "并非真实主机名。请确认你知道这个网关。");
    }
    if (info.expired) {
      warns.push("<b>证书已过期</b>。");
    }
    $("certwarn").innerHTML = warns.length
      ? '<div class="warn' + (info.expired ? " bad" : "") + '">' + warns.join("<br>") + "</div>"
      : "";

    const done = (ok) => {
      $("certmask").classList.remove("on");
      $("cert-yes").onclick = null;
      $("cert-no").onclick = null;
      resolve(ok);
    };
    $("cert-yes").onclick = () => done(true);
    $("cert-no").onclick = () => done(false);
    $("certmask").classList.add("on");
  });
}

$("go").onclick = async () => {
  const btn = $("go");
  try {
    if (btn.textContent === "断开") {
      userStopped = true;
      await invoke("disconnect");
      return;
    }
    userStopped = false;
    // 以**已保存的 profile 为基底**，只覆盖表单里可见的那几个字段。
    //
    // 之前是从零重建 `{id,name,server,protocol,username,remember_password}`，
    // 于是 profile 的其余部分全部丢失：
    //   - `advanced.server_cert_pin` → 每次连接都重新弹证书确认
    //   - `auth_group`（分组下拉）→ 静默失效
    //   - `ca_file` / `no_dtls` / `mtu` / `pfs` … → 静默失效
    // 用户配了却不生效，且没有任何提示。
    //
    // `protocol` 不设在这里：省略即用默认值 AnyConnect，避免在前端
    // 硬编码协议名 —— Rust 侧 serde 形式必须与 `as_arg()` 一致
    // （anyconnect 而非 any-connect），两边各写一份容易分叉。
    const saved = profiles.find(p => p.id === current);
    const profile = {
      ...(saved ?? {}),
      id: current ?? crypto.randomUUID(),
      name: saved?.name ?? ($("server").value.split("/")[0] || "vpn"),
      server: $("server").value.trim(),
      username: $("username").value.trim() || null,
      remember_password: $("remember").checked,
    };
    if (btn.textContent === "连接") {
      // 没有 pin 才需要确认；已有 pin 时 openconnect 会自己做精确匹配，
      // 证书变了会直接失败，无需打扰用户。
      if (!profile.advanced?.server_cert_pin) {
        msg("正在读取服务器证书…");
        let info;
        try {
          info = await invoke("probe_server_cert", { server: profile.server });
        } catch (e) {
          msg("无法读取服务器证书: " + e, true);
          return;
        }
        const ok = await certDialog(info);
        if (!ok) {
          msg("已拒绝该证书，未发起连接", true);
          return;
        }
        profile.advanced = { ...(profile.advanced || {}),
                             server_cert_pin: info.pinSha256 };
        // 持久化，下次不再询问
        try {
          await invoke("trust_server_cert",
                       { profileId: profile.id, pin: info.pinSha256 });
        } catch (e) {
          msg("证书 pin 保存失败（本次仍可连接）: " + e, true);
        }
      }

      // 「正在连接…」必须在 invoke **之前**写。
      //
      // 写在 await 之后会丢原因：一次连接会喷几十条日志 + 若干状态
      // 事件，全是独立的 IPC 消息；事件密集时 invoke 的响应排在它们
      // 后面，于是这句「正在连接…」反而在失败原因之后执行，把真正
      // 的错误盖成一句永远转圈的提示（实测：密码为空导致的失败被盖掉）。
      msg("正在连接…");
      await invoke("connect", {
        profile,
        password: $("password").value || null,
        cookie: null,
      });
      $("password").value = "";
    }
  } catch (e) {
    msg(String(e), true);
  }
};

// ---- 特权助手 ----
async function refreshTray() {
  let text;
  try {
    const t = await invoke("tray_status");
    text = t.installed
      ? "关闭窗口会缩到菜单栏图标，右键图标可断开或退出。"
      : "菜单栏图标不可用（缺少托盘图标），关闭窗口将直接退出 App。";
  } catch (e) {
    text = "无法检测菜单栏图标: " + e;
  }
  // 只在设置页展示。连接页原来也有一个同名元素，但它和状态区
  // 的按钮绑在一起，已经移除了 —— 关闭窗口本来就缩到托盘，
  // 在连接表单上方挂一句「去菜单栏断开或退出」纯属噪音。
  $("tray-msg2").textContent = text;
}

async function refreshHelper() {
  try {
    const h = await invoke("helper_status");
    $("helper-msg").textContent = h.message;
    if (h.privileged) {
      $("helper-btn").style.display = "none";
      $("helper-cmd").style.display = "none";
    } else {
      $("helper-btn").style.display = "";
      $("helper-cmd").style.display = "";
      $("helper-cmd").textContent = h.elevate_command ?? "";
    }
  } catch (e) {
    $("helper-msg").textContent = "无法检测助手状态: " + e;
  }
}

async function startHelper() {
  const btn = $("helper-btn");
  btn.disabled = true;
  const isMac = navigator.userAgent.includes("Macintosh");
  btn.textContent = isMac ? "申请中…" : "等待授权…";
  $("helper-msg").textContent = isMac
    ? "正在向系统申请注册特权助手…"
    : "请在系统弹窗中输入管理员密码";
  try {
    const state = await invoke("helper_start_elevated");
    const ok = await invoke("helper_wait_ready", { timeoutMs: 30000 });

    if (ok) {
      $("helper-msg").textContent = "特权助手已就绪";
      btn.style.display = "none";
      $("helper-cmd").style.display = "none";
    } else if (isMac) {
      // macOS 的 SMAppService 不会弹密码框 ——
      // 必须在「系统设置 → 通用 → 登录项」手动批准。
      $("helper-msg").textContent =
        "请到「系统设置 → 通用 → 登录项」打开 OC GUI 的开关（系统状态：" + state + "）";
      btn.textContent = "打开系统设置";
      btn.onclick = () => invoke("open_system_settings");
    } else {
      $("helper-msg").textContent = "助手未能在 30 秒内就绪（可能取消了授权）";
      btn.textContent = "提权启动";
      btn.onclick = startHelper;
    }
  } catch (e) {
    $("helper-msg").textContent = "启动失败: " + e;
    btn.textContent = "提权启动";
    btn.onclick = startHelper;
  }
  btn.disabled = false;
}

listen("vpn://state", e => setState(e.payload.state));
listen("vpn://stats", e => {
  // 隧道已断时迟到的统计行不该把归零后的计数显示出来。
  if (connectedAt === null) return;
  lastStats = e.payload;
  renderStats();
});
listen("vpn://cause", e => {
  const c = e.payload.cause ?? {};
  // 权限问题要引导用户启动助手，而不是让用户反复重试
  if (c.hint && c.kind === "privilege_required") {
    msg(c.hint, true);
    refreshHelper();
    $("helper-card").scrollIntoView({ behavior: "smooth", block: "nearest" });
    return;
  }
  // reason 可能为空（helper 通道下 Finished 事件不重复传 reason，
  // 原因由 message_key 决定）—— 此时不要显示空白。
  const text = c.reason && c.reason.length
    ? c.reason
    : "已结束：" + t(e.payload.message_key, e.payload.reason);
  endedByCause = true;
  msg(text, e.payload.retryable !== true);
  if (e.payload.retryable) $("password").focus();
});
listen("vpn://log", e => {
  const box = $("log");
  box.textContent += e.payload.line + "\n";
  // 实时日志视图：始终跟随最新一行。
  //
  // 之前只在「原本贴着底部」时才滚动，但 textContent 赋值本身就抬高
  // 了 scrollHeight，第一条把内容撑出可视区之后 atBottom 永远为假，
  // 于是日志停在开头几行 —— 排查时最关键的那几行（fgets、auth失败、
  // Exited）反而看不到。
  box.scrollTop = box.scrollHeight;
  if (box.textContent.length > 200000) box.textContent = box.textContent.slice(-100000);
});

// ---- 事件绑定 ----
//
// 刻意**不用** HTML 里的 `onclick="fn()"` 内联属性：Tauri 的 CSP 是
// `default-src 'self'`，`script-src` 回落到它，**内联脚本与内联事件
// 处理器都会被拦**。
//
// 这个坑的实际后果很隐蔽：App 能正常打开、界面完整显示，但 JS 一行
// 都没执行 —— 下拉框是空的、「检测中…」永远卡住、点「连接」毫无反应，
// 而且没有任何报错。症状看起来像"功能没做完"，而不是"权限被拒"。
//
// 因此 `script-src` 不需要 `'unsafe-inline'`，CSP 可以保持严格。

$("tab-conn").addEventListener("click", () => tab("conn"));
$("tab-prof").addEventListener("click", () => tab("prof"));
$("tab-log").addEventListener("click", () => tab("log"));
$("profile").addEventListener("change", render);
$("helper-btn").addEventListener("click", startHelper);
$("save-prof").addEventListener("click", saveProfile);
$("clear-log").addEventListener("click", () => { $("log").textContent = ""; });
$("tab-cfg").addEventListener("click", () => tab("cfg"));

// 唤回窗口只剩设置页的「显示图标」一个入口。
//
// ⚠️ 这里删掉了连接页原有的「菜单栏」与「退出」两个按钮。
// 「退出」删得掉是因为关闭窗口 = 缩到托盘，而托盘菜单里有「断开」
// 和「退出」；真正的退出路径还在。若哪天托盘装不上，托盘菜单连
// 同退出入口会一起消失 —— 那种情况下「无托盘即允许正常关闭」
// （tray.rs 的 on_window_event）就是唯一的兜底。
$("btn-show2").addEventListener("click", () => invoke("show_main_window"));

// 启动序列：**每一步独立**，失败不许掐断后续步骤。
//
// 之前是一条顶层 await 链：`loadProfiles()` 一旦抛错，
// `refreshHelper()` / `setState()` / `backend_info` 都不执行，
// 而且模块顶层抛出的异常没有任何出口 —— 用户只看到界面停在
// 「检测中…」、按钮点了没反应，完全无从判断出了什么事。
async function boot() {
  try {
    await loadProfiles();
  } catch (e) {
    msg("加载配置失败: " + e, true);
    console.error("loadProfiles", e);
  }
  try {
    await refreshTray();
  } catch (e) {
    console.error("refreshTray", e);
  }
  try {
    await refreshHelper();
  } catch (e) {
    msg("检测特权助手失败: " + e, true);
    console.error("refreshHelper", e);
  }
  setState("idle");
  try {
    const i = await invoke("backend_info");
    if (!i.openconnect_version) msg("未找到 openconnect，请先安装", true);
  } catch (e) {
    console.error("backend_info", e);
  }
}
await boot();
