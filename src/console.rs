//! The binary uses the Windows GUI subsystem (no console flash when
//! launched from Explorer), so CLI invocations must re-attach to the
//! parent terminal's console for println!/eprintln! to reach the user.

#[cfg(windows)]
pub fn attach_parent_console() {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_WRITE, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::Console::{
        AttachConsole, SetStdHandle, ATTACH_PARENT_PROCESS, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
    };

    unsafe {
        if AttachConsole(ATTACH_PARENT_PROCESS).is_err() {
            return; // launched from Explorer/UAC — no parent console, GUI only
        }
        let name: Vec<u16> = "CONOUT$".encode_utf16().chain(std::iter::once(0)).collect();
        if let Ok(h) = CreateFileW(
            PCWSTR(name.as_ptr()),
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        ) {
            let _ = SetStdHandle(STD_OUTPUT_HANDLE, h);
            let _ = SetStdHandle(STD_ERROR_HANDLE, h);
        }
    }
}

#[cfg(not(windows))]
pub fn attach_parent_console() {}
