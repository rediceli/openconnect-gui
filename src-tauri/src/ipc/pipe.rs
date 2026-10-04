//! Windows named pipe 客户端。
//!
//! # 与 Unix socket 的对应关系
//!
//! `CreateFileW` 打开 pipe 拿到 `HANDLE`，包成 [`ClientPipe`] 后
//! 实现 `Read`/`Write`，上层（`client.rs`）就能和 Unix 用
//! `UnixStream` 一模一样的代码。**只有这里知道是 Windows。**
//!
//! # 授权不在这里
//!
//! 客户端不需要（也不应该）自己判断能不能连 —— pipe 的 DACL 在 helper
//! 创建 pipe 时就定好了，`CreateFileW` 要么成功要么
//! `ERROR_ACCESS_DENIED`。所以这里没有 uid 校验，也不该有。

use oc_proto::authz::per_user_pipe_name;
use std::os::windows::io::FromRawHandle;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// `GENERIC_READ | GENERIC_WRITE`
const RW: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE;

/// `TokenUser`（`TOKEN_INFORMATION_CLASS`）
const TOKEN_USER_CLASS: i32 = 1;
/// `SDDL_REVISION_1`
const SDDL_REVISION_1: u32 = 1;
/// ERROR_PIPE_BUSY：所有 pipe 实例都被占着（说明 helper 在，只是忙）
const ERROR_PIPE_BUSY: u32 = 231;

fn last_error() -> std::io::Error {
    std::io::Error::last_os_error()
}

/// 取当前进程 SID 的字符串形式（如 `S-1-5-21-...-1001`）。
///
/// GUI 以普通用户身份运行，所以这里拿到的就是用户 SID，
/// 与 helper 构造 pipe 名时用的那个一致。
pub fn current_sid() -> Result<String, std::io::Error> {
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(last_error());
        }
        let mut needed: u32 = 0;
        GetTokenInformation(token, 1, std::ptr::null_mut(), 0, &mut needed);
        if needed == 0 {
            CloseHandle(token);
            return Err(std::io::Error::other("GetTokenInformation 未返回所需大小"));
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
            return Err(last_error());
        }
        CloseHandle(token);

        let user = buf.as_ptr().cast::<TOKEN_USER>();
        let mut sid_ptr: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW((*user).User.Sid, &raw mut sid_ptr) == 0 {
            return Err(last_error());
        }
        let mut len = 0usize;
        while *sid_ptr.add(len) != 0 {
            len += 1;
        }
        // SID 是 UTF-16
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(
            sid_ptr as *const u16,
            len,
        ));
        LocalFree(sid_ptr.cast());
        Ok(s)
    }
}

/// 以当前用户 SID 推出 pipe 名。
pub fn pipe_name_for_current_user() -> Result<String, std::io::Error> {
    Ok(per_user_pipe_name(&current_sid()?))
}

/// 连到 helper 的 named pipe。
pub struct ClientPipe {
    file: std::fs::File,
}

impl std::fmt::Debug for ClientPipe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientPipe")
    }
}

impl ClientPipe {
    pub fn connect() -> std::io::Result<Self> {
        Self::connect_to(&pipe_name_for_current_user()?)
    }

    pub fn connect_to(name: &str) -> std::io::Result<Self> {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // 让 DACL 限制生效：不传 SECURITY_ATTRIBUTES，
        // 只给「允许的最大权限」，实际权限仍由 pipe 自己的 DACL 决定。
        let sd = default_client_sd()?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };

        let handle: HANDLE = unsafe {
            CreateFileW(
                wide.as_ptr(),
                RW,
                0, // 不共享：pipe 一次只服务一个客户端
                &sa,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(last_error());
        }
        Ok(Self {
            file: unsafe { std::fs::File::from_raw_handle(handle.cast()) },
        })
    }

    pub fn try_clone(&self) -> std::io::Result<Self> {
        Ok(Self {
            file: self.file.try_clone()?,
        })
    }
}

impl std::io::Read for ClientPipe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        std::io::Read::read(&mut self.file, buf)
    }
}

impl std::io::Write for ClientPipe {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut self.file, buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.file)
    }
}

/// 客户端侧的最小安全描述符：只要求「读」权限。
///
/// pipe 端的 DACL 才是授权依据；这里如果放开 `FILE_GENERIC_WRITE`
/// 会让 pipe server 侧的 ACL 变成可写，安全描述符的语义就乱了
/// （client 对象本该只用来读）。
fn default_client_sd() -> std::io::Result<PSECURITY_DESCRIPTOR> {
    // 「只读」的最小 SDDL：D:P(A;;0x120089;;;IU) —— IU = Interactive Users
    let sddl: Vec<u16> = "D:P(A;;0x120089;;;IU)"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let mut len = 0u32;
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            &mut len,
        )
    };
    if ok == 0 {
        return Err(last_error());
    }
    Ok(sd)
}

/// 轮询等待 pipe 出现。
///
/// GUI 在用户点「提权启动」后需要等 helper 起来。pipe 不存在时
/// `WaitNamedPipeW` 会等待而不是立刻失败，正好用来做这个轮询。
pub fn wait_for_pipe(name: &str, timeout_ms: u32) -> bool {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let start = std::time::Instant::now();
    loop {
        let remain = timeout_ms.saturating_sub(start.elapsed().as_millis() as u32);
        if remain == 0 {
            return false;
        }
        let ok = unsafe { WaitNamedPipeW(wide.as_ptr(), 300) };
        if ok != 0 {
            return true;
        }
        // ERROR_PIPE_BUSY 表示所有实例都被占着 —— 那是「连得上」，
        // 也算就绪
        if last_error().raw_os_error() == Some(ERROR_PIPE_BUSY as i32) {
            return true;
        }
    }
}

/// 以 UAC 提权启动 helper。
///
/// 对应 Linux 的 `pkexec`。用 `ShellExecuteW` + `runas` verb 而不是
/// `CreateProcessW` + 调 `ShellExecuteEx` 手动提权 —— 前者由 shell
/// 负责弹 UAC 对话框，语义清晰且不会漏掉 consent 提示。
///
/// 返回 `Ok(())` 只表示 UAC 已接受，调用方应随后轮询 pipe 是否就绪。
pub fn spawn_elevated(program: &std::path::Path) -> Result<(), std::io::Error> {
    if !program.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("helper 不存在: {}", program.display()),
        ));
    }
    use std::os::windows::ffi::OsStrExt;
    let file: Vec<u16> = program.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let verb: Vec<u16> = "runas".encode_utf16().chain(std::iter::once(0)).collect();

    // ShellExecuteW 的返回值是 HINSTANCE（不是错误码），> 32 表示成功
    let rc: isize = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            std::ptr::null(), // 无参数
            std::ptr::null(),
            SW_HIDE,
        )
    } as isize;
    // ShellExecuteW 成功返回值 > 32。32 以下是错误码。
    if rc <= 32 {
        return Err(std::io::Error::other(format!(
            "ShellExecuteW(runas) 返回 {rc}（UAC 被拒绝或 helper 启动失败）"
        )));
    }
    Ok(())
}

use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;