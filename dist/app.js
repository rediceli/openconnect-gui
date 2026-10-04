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
  for (const k of ["conn","prof","log"]) {
    $("v-"+k).classList.toggle("hide", k !== which);
    $("tab-"+k).classList.toggle("on", k === which);
  }
}

function msg(text, isErr) {
  const el = $("msg");
  el.textContent = text;
  el.className = "msg" + (isErr ? " err" : "");
}

function setState(s) {
  const pill = $("state");
  pill.textContent = STATE_LABEL[s] ?? s;
  pill.className = "pill s-" + s;
  $("go").textContent = (s === "connected") ? "断开" : "连接";
  $("go").disabled = ["connecting","authenticating","configuring","reconnecting"].includes(s);
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
      await invoke("disconnect");
      return;
    }
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

      await invoke("connect", {
        profile,
        password: $("password").value || null,
        cookie: null,
      });
      $("password").value = "";
      msg("正在连接…");
    }
  } catch (e) {
    msg(String(e), true);
  }
};

// ---- 特权助手 ----
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
  msg(text, e.payload.retryable !== true);
  if (e.payload.retryable) $("password").focus();
});
listen("vpn://log", e => {
  const box = $("log");
  const atBottom = box.scrollTop + box.clientHeight >= box.scrollHeight - 20;
  box.textContent += e.payload.line + "\n";
  if (atBottom) box.scrollTop = box.scrollHeight;
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
