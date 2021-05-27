use winapi::um::processthreadsapi::{
    GetCurrentProcess, GetStartupInfoW, OpenProcess, LPSTARTUPINFOW, STARTUPINFOW,
};

use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};

use crate::errorhandling::WinAPIError;
use winapi::shared::minwindef::{BOOL, DWORD, FALSE, PBOOL, TRUE};
use winapi::shared::ntdef::NULL;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::winnt::{HANDLE, PHANDLE, PVOID};

#[derive(Debug)]
/// Token encapsulates a security token
/// A token identifies the security context a process or thread is running under
pub struct Process {
    handle: HANDLE,
}

impl Default for Process {
    // This is the default, invalid value of a security token
    fn default() -> Self {
        Process {
            handle: INVALID_HANDLE_VALUE,
        }
    }
}

/// the Drop trait is called when the lifetime of the Process expires (aka the destructor)
impl Drop for Process {
    /// Probably the most important function of this whole file, making sure we release the handle to the process
    fn drop(&mut self) {
        unsafe {
            if self.handle != INVALID_HANDLE_VALUE && self.handle != NULL {
                CloseHandle(self.handle);
            }
        }
    }
}

impl Process {
    /// Returns the current process, mode is all access
    pub fn from_current() -> Result<Process, WinAPIError> {
        unsafe {
            Ok(Process {
                handle: GetCurrentProcess(),
            })
        }
    }

    pub fn from_id(mode: DWORD, inherit: BOOL, id: DWORD) -> Result<Process, WinAPIError> {
        unsafe {
            let h = OpenProcess(mode, inherit, id);

            if h == NULL {
                let err = GetLastError();
                log::debug!("error opening process with id, GetLastError() : {}", err);
                return Err(WinAPIError::LastError(err));
            }

            Ok(Process { handle: h })
        }
    }

    pub fn is_valid(&self) -> bool {
        self.handle != INVALID_HANDLE_VALUE || self.handle != NULL
    }

    pub fn startup_info(&self) -> Box::<STARTUPINFOW> {
        if !self.is_valid() {
            panic!("invalid process");
        }
        unsafe {
            let mut si = Box::<STARTUPINFOW>::new(std::mem::zeroed());

            GetStartupInfoW(si.as_mut());

            si
        }
    }

    // pub fn create(
    //     lpApplicationName: LPCWSTR,
    //     lpCommandLine: LPWSTR,
    //     lpProcessAttributes: LPSECURITY_ATTRIBUTES,
    //     lpThreadAttributes: LPSECURITY_ATTRIBUTES,
    //     bInheritHandles: BOOL,
    //     dwCreationFlags: DWORD,
    //     lpEnvironment: LPVOID,
    //     lpCurrentDirectory: LPCWSTR,
    //     lpStartupInfo: LPSTARTUPINFOW,
    //     lpProcessInformation: LPPROCESS_INFORMATION) -> Result<Process, WinAPIError> {

    //     Ok(Process {
    //         handle: INVALID_HANDLE_VALUE
    //     })
    // }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn current_process() {
        let p = Process::from_current();

        assert!(p.is_ok());
    }

    #[test]
    pub fn current_process_by_id() {
        use winapi::um::processthreadsapi::GetCurrentProcessId;
        use winapi::um::winnt::SYNCHRONIZE;

        unsafe {
            let p = Process::from_id(SYNCHRONIZE, FALSE, GetCurrentProcessId());
            assert!(p.is_ok());
        }
    }

    #[test]
    pub fn get_startup_info() {
        let p = Process::from_current().expect("getting current process should never fail");

        let si = p.startup_info();
        
        println!("Desktop: {:?}", String::from_utf16(si.lpDesktop));
    }
}
