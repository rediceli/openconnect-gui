//! Windows 特权助手（named pipe）。
//!
//! # 授权模型：与 Linux 的差异
//!
//! | | Linux | Windows |
//! |---|---|---|
//! | 端点 | Unix socket | named pipe（全局命名空间 `\\.\pipe\`） |
//! | 授权 | polkit → 每用户 socket `0600` → 运行时 uid 复检 | **DACL**（创建 pipe 时指定安全描述符） |
//!
//! Windows 上没有「连上了再校验」这回事 —— named pipe 的 DACL 在
//! `CreateNamedPipeW` 时就写进了安全描述符，非授权方**根本连不上**。
//! 所以这里没有 `authorize()` 运行时检查。
//!
//! ⚠️ **不能用 `Local\` 命名空间**：`Local\` 的 pipe 由创建进程拥有，
//! SYSTEM 创建的 pipe 普通用户连不上。要让普通用户能连提权进程创建的
//! pipe，必须用全局命名空间，靠 DACL 而非命名空间隔离。
//!
//! ⚠️ **DACL 不能放行 Administrators/Everyone** —— 那等于任何管理员
//! 账号都能驱动这个 SYSTEM 提权管道，与 Linux 上「按 uid 白名单、
//! 不按组」的原则相反。只放行「启动 helper 的那个用户 SID」+ SYSTEM。
//!
//! ⚠️ **`PIPE_REJECT_REMOTE_CLIENTS` 不能省**：否则 SMB 可能把 pipe
//! 暴露到网络上，任何能访问本机 445 端口的域内主机都能连上这个
//! SYSTEM 管道。

#[cfg(windows)]
mod win {
    use oc_proto::authz::{per_user_pipe_name, pipe_dacl};
    use oc_proto::{
        HelperError, Request, Response, PROTOCOL_VERSION, validate_args, validate_program,
    };
    use std::io::{BufRead, BufReader, Write};
    use std::os::windows::io::FromRawHandle;
    // 常量全部从 windows-sys 导入，不手写数值 ——
    // 手写时把 PIPE_UNLIMITED_INSTANCES 写成了 0xFFFFFFFF，
    // 实际 MSDN 定义是 255。这种错误编译器不会报，运行时才炸。
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows_sys::Win32::System::Pipes::{
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    /// `TOKEN_QUERY`
    const TOKEN_QUERY: u32 = 0x0008;
    /// `TokenUser`（`TOKEN_INFORMATION_CLASS`）
    const TOKEN_USER_CLASS: i32 = 1;
    /// `SDDL_REVISION_1`
    const SDDL_REVISION_1: u32 = 1;

    type Handle = *mut std::ffi::c_void;

    fn last_error() -> String {
        std::io::Error::last_os_error().to_string()
    }

    /// 取当前进程的 SID 字符串（如 `S-1-5-21-...-1001`）。
    ///
    /// pipe 名里带 SID、DACL 里也只放行它 —— 这样不同用户的 helper
    /// 互不干扰，也不会出现「A 用户的 helper 被 B 用户连上」。
    /// # Safety
    /// 内部全部是 Win32 调用，无外部指针参数，安全。
    fn current_sid() -> Result<String, String> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_USER};
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        unsafe {
            let mut token = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(format!("OpenProcessToken: {}", last_error()));
            }

            // 第一次调用只为拿需要的字节数（这是 Win32 的固定 idiom）
            let mut needed: u32 = 0;
            GetTokenInformation(
                token,
                TOKEN_USER_CLASS,
                std::ptr::null_mut(),
                0,
                &mut needed,
            );
            if needed == 0 {
                CloseHandle(token);
                return Err("GetTokenInformation 未返回所需大小".into());
            }

            let mut buf = vec![0u8; needed as usize];
            if GetTokenInformation(
                token,
                TOKEN_USER_CLASS,
                buf.as_mut_ptr().cast(),
                needed,
                &raw mut needed,
            ) == 0
            {
                CloseHandle(token);
                return Err(format!("GetTokenInformation: {}", last_error()));
            }
            CloseHandle(token);

            let user = buf.as_ptr().cast::<TOKEN_USER>();
            let mut sid_ptr: *mut u16 = std::ptr::null_mut();
            if ConvertSidToStringSidW((*user).User.Sid, &raw mut sid_ptr) == 0 {
                return Err(format!("ConvertSidToStringSidW: {}", last_error()));
            }
            let mut len = 0usize;
            while *sid_ptr.add(len) != 0 {
                len += 1;
            }
            // SID 字符串是 UTF-16，必须用 from_utf16_lossy（不是 from_utf8_lossy）
            let s =
                String::from_utf16_lossy(std::slice::from_raw_parts(sid_ptr as *const u16, len));
            // ConvertSidToStringSidW 分配的字符串必须用 LocalFree 释放，
            // 不能靠 Rust 的 drop —— 分配器不同（LocalAlloc vs Rust 的）
            windows_sys::Win32::Foundation::LocalFree(sid_ptr.cast());
            Ok(s)
        }
    }

    /// 由 SDDL 生成安全描述符。
    ///
    /// 权限位 `0x12019b` = `FILE_GENERIC_READ | FILE_GENERIC_WRITE`。
    fn security_attributes(sid: &str) -> Result<SECURITY_ATTRIBUTES, String> {
        use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;

        let sddl = pipe_dacl::SDDL_TEMPLATE.replace("{SID}", sid);
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();

        let mut sd: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut len: u32 = 0;
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                &raw mut len,
            )
        };
        if ok == 0 {
            return Err(format!(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW({sddl}): {}",
                last_error()
            ));
        }
        Ok(SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        })
    }

    fn serve() -> Result<(), String> {
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Pipes::{ConnectNamedPipe, CreateNamedPipeW};

        let sid = current_sid()?;
        let name = per_user_pipe_name(&sid);
        let sa = security_attributes(&sid)?;
        let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

        let pipe: Handle = unsafe {
            CreateNamedPipeW(
                wide_name.as_ptr(),
                PIPE_ACCESS_DUPLEX | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_UNLIMITED_INSTANCES,
                1,     // nMaxInstances：一次只服务一个客户端（openconnect 是独占资源）
                65536, // nOutBufferSize
                65536, // nInBufferSize
                0,     // nDefaultTimeOut
                &sa,
            )
        };
        // ⚠️ 第 8 个参数 lpSecurityAttributes 必须传 &sa。
        // 传 null 会让 pipe 用**默认 DACL**（在某些配置下放行 Everyone），
        // 那样整个提权通道的授权就失效了 —— 而这不会报任何错，
        // 只会「莫名其妙什么都能连」。
        if pipe == INVALID_HANDLE_VALUE {
            return Err(format!("CreateNamedPipeW({name}): {}", last_error()));
        }
        eprintln!("helper listening on {name} (sid={sid})");

        loop {
            let rc = unsafe { ConnectNamedPipe(pipe, std::ptr::null_mut()) };
            if rc == 0 {
                let err = std::io::Error::last_os_error();
                // 客户端在 ConnectNamedPipe 返回前就断开了 —— 常见于
                // GUI 启动后立刻退出。pipe 实例仍然有效，重试即可。
                eprintln!("helper: 握手前客户端断开（{err}），继续等待");
                continue;
            }
            // 借用 pipe 构造 File；try_clone 走 DuplicateHandle，
            // 因此两个 File 各自独立拥有句柄，结束时都会正确关闭。
            let file = unsafe { std::fs::File::from_raw_handle(pipe) };
            let mut out = match file.try_clone() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("helper: try_clone 失败: {e}");
                    continue;
                }
            };
            let mut reader = BufReader::new(file);

            loop {
                let mut line = String::new();
                match read_line(&mut reader, &mut line) {
                    Ok(0) => break, // 客户端正常关闭
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("helper: 读取失败: {e}");
                        break;
                    }
                }
                let trimmed = line.trim_end_matches(['\r', '\n']);
                if trimmed.is_empty() {
                    continue;
                }
                if trimmed == r#"{"op":"Shutdown"}"# {
                    drop(reader);
                    let _ = out.flush();
                    drop(out);
                    unsafe { CloseHandle(pipe) };
                    return Ok(());
                }
                let resp = dispatch(trimmed);
                let _ = writeln!(out, "{}", serde_json::to_string(&resp).unwrap());
                let _ = out.flush();
            }
        }
    }

    fn read_line(r: &mut impl BufRead, out: &mut String) -> std::io::Result<usize> {
        let mut bytes = Vec::new();
        let n = r.read_until(b'\n', &mut bytes)?;
        out.push_str(&String::from_utf8_lossy(&bytes));
        Ok(n)
    }

    fn dispatch(line: &str) -> Response {
        let req: Result<Request, _> = serde_json::from_str(line);
        match req {
            Err(e) => Response::Failed {
                error: HelperError::Internal {
                    message: format!("bad json: {e}"),
                },
            },
            Ok(Request::Hello { version, .. }) => {
                if version != PROTOCOL_VERSION {
                    Response::Failed {
                        error: HelperError::ProtocolMismatch {
                            expected: PROTOCOL_VERSION,
                            got: version,
                        },
                    }
                } else {
                    Response::Ready {
                        version: PROTOCOL_VERSION,
                        authorized: true,
                        connected: false,
                    }
                }
            }
            Ok(Request::Start { args, server, .. }) => start_openconnect(&args, &server),
            Ok(Request::Stop | Request::Status) => Response::Status {
                connected: false,
                pid: None,
                uptime_secs: None,
            },
            Ok(Request::Shutdown) => Response::Status {
                connected: false,
                pid: None,
                uptime_secs: None,
            },
        }
    }

    /// 与 Linux 版同一条边界：**只允许执行 openconnect**。
    ///
    /// Windows 上同样必须挡住 `--script-tun`：它能让 helper 以
    /// SYSTEM 身份执行任意脚本。`validate_args` 是共享代码，
    /// 跨平台行为一致（见 oc-proto 的测试）。
    fn start_openconnect(args: &[String], server: &str) -> Response {
        let exe = std::env::var("OCGUI_OPENCONNECT").unwrap_or_else(|_| "openconnect.exe".into());
        if let Err(e) = validate_program(std::path::Path::new(&exe)) {
            return Response::Failed { error: e };
        }
        if let Err(e) = validate_args(args, server) {
            return Response::Failed { error: e };
        }
        // TODO(P1): spawn openconnect + stdio 转发行协议 + Tracker。
        // 已确认可用的方案见 P1-DESIGN §6.3.11。
        Response::Failed {
            error: HelperError::Internal {
                message: format!("Windows spawn 未实现（已通过协议校验，{n} 个参数）", n = args.len()),
            },
        }
    }

    pub fn run() -> ! {
        if let Err(e) = serve() {
            eprintln!("helper: {e}");
            std::process::exit(1);
        }
        // 常驻直到 GUI 主动 Shutdown
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }
}

fn main() {
    #[cfg(windows)]
    win::run();

    #[cfg(not(windows))]
    {
        eprintln!("此 helper 仅适用于 Windows");
        std::process::exit(2);
    }
}