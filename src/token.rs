use std::ptr::null_mut;

use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};

use winapi::um::winnt::{HANDLE, PHANDLE, PVOID};

use winapi::um::processthreadsapi::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};
use winapi::um::securitybaseapi::{DuplicateToken, GetTokenInformation};
use winapi::um::winnt::{
    TokenElevationType, TokenElevationTypeLimited, TokenLinkedToken, TokenType,
    TOKEN_ELEVATION_TYPE, TOKEN_LINKED_TOKEN, TOKEN_TYPE,
};

use winapi::um::securitybaseapi::{CheckTokenMembership, CreateWellKnownSid};
use winapi::um::winnt::{
    WinBuiltinAdministratorsSid, PSID, SECURITY_MAX_SID_SIZE, WELL_KNOWN_SID_TYPE,
};

use crate::errorhandling::WinAPIError;
use winapi::shared::minwindef::{BOOL, DWORD, FALSE, PBOOL, TRUE};
use winapi::um::errhandlingapi::GetLastError;

#[derive(Debug)]
/// Token encapsulates a security token
/// A token identifies the security context a process or thread is running under
pub struct Token {
    h_token: HANDLE,
}

impl Default for Token {
    // This is the default, invalid value of a security token
    fn default() -> Self {
        Token {
            h_token: INVALID_HANDLE_VALUE,
        }
    }
}

/// the Drop trait is called when the lifetime of the Token expires (aka the destructor)
impl Drop for Token {
    /// Probably the most important function of this whole file, making sure we release the token
    fn drop(&mut self) {
        unsafe {
            if self.h_token != INVALID_HANDLE_VALUE {
                CloseHandle(self.h_token);
            }
        }
    }
}

/// the Clone trait is called when a copy of the token needs to be created
impl Clone for Token {
    /// Windows allows for a security token to be duplicated
    /// This copy will have the same type as the original token
    fn clone(&self) -> Self {
        // Clone mut duplicate the token "as is", using it's original type (Impersonation or Primary)
        self.duplicate(self.token_type().expect("unable to determine token type"))
            .expect("failed to duplicate token")
    }
}

impl Token {
    /// Returns the token associated with the process' handle.
    /// mode is the token acces mode, valid values are: TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_QUERY_SOURCE
    pub fn from_process(handle: HANDLE, mode: DWORD) -> Result<Token, WinAPIError> {
        let mut token: HANDLE = INVALID_HANDLE_VALUE;
        unsafe {
            if OpenProcessToken(handle, mode, &mut token) == FALSE {
                let err = GetLastError();
                log::debug!("Error getting process token GetLastError: {}", err);
                return Err(WinAPIError::LastError(err));
            }
        }

        Ok(Token { h_token: token })
    }

    /// Returns the token associated with the current process
    /// mode is the token acces mode, valid values are: TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_QUERY_SOURCE
    pub fn from_current_process(mode: DWORD) -> Result<Token, WinAPIError> {
        unsafe { Self::from_process(GetCurrentProcess(), mode) }
    }

    /// Returns the token associated with the thread's handle.
    /// mode is the token acces mode, valid values are: TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_QUERY_SOURCE
    pub fn from_thread(
        handle: HANDLE,
        mode: DWORD,
        open_as_self: BOOL,
    ) -> Result<Token, WinAPIError> {
        let mut token: HANDLE = INVALID_HANDLE_VALUE;
        unsafe {
            if OpenThreadToken(handle, mode, open_as_self, &mut token) == FALSE {
                let err = GetLastError();
                log::debug!("Error getting process token GetLastError: {}", err);
                return Err(WinAPIError::LastError(err));
            }
        }

        Ok(Token { h_token: token })
    }

    /// Returns the token associated with the current thread calling this function.
    pub fn from_current_thread(mode: DWORD, open_as_self: BOOL) -> Result<Token, WinAPIError> {
        unsafe { Token::from_thread(GetCurrentThread(), mode, open_as_self) }
    }

    /// Returns the token's type (Primary or Impersonation)
    pub fn token_type(&self) -> Result<TOKEN_TYPE, WinAPIError> {
        unsafe {
            let mut token_type: TOKEN_TYPE = std::mem::zeroed();
            let token_type_ptr = &mut token_type as *mut _ as PVOID;
            let mut returned_length: DWORD = 0u32;
            let size = std::mem::size_of::<TOKEN_TYPE>() as u32;
            //let size = 4u32;
            if GetTokenInformation(
                self.h_token,
                TokenType,
                token_type_ptr,
                size,
                &mut returned_length,
            ) == 0i32
            {
                let err = GetLastError();
                log::debug!(
                    "Error getting token linked information GetLastError: {}",
                    err
                );
                return Err(WinAPIError::LastError(err));
            }
            Ok(token_type)
        }
    }

    /// Duplicates the token and returns the token's copy
    /// The type argument allows to obtain a copy of the seld token with a different type
    pub fn duplicate(&self, tokentype: TOKEN_TYPE) -> Result<Token, WinAPIError> {
        unsafe {
            let mut dup_token: HANDLE = std::ptr::null_mut();
            let dup_token_ptr = &mut dup_token as PHANDLE;
            if DuplicateToken(self.h_token, tokentype, dup_token_ptr) == FALSE {
                let err = GetLastError();
                log::debug!(
                "Error trying to duplicate primary token into an impersonation token GetLastError: {}",
                err);
                return Err(WinAPIError::LastError(err));
            }
            Ok(Token { h_token: dup_token })
        }
    }

    /// Checks if the self token is a member of a specific well known group
    pub fn is_member(&self, known_sid: WELL_KNOWN_SID_TYPE) -> Result<bool, WinAPIError> {
        unsafe {
            let mut admin_sid = vec![0u8; SECURITY_MAX_SID_SIZE];
            let admin_sid_ptr = admin_sid.as_mut_ptr() as PVOID;
            let mut sid_size = (std::mem::size_of::<u8>() * SECURITY_MAX_SID_SIZE) as DWORD;

            if CreateWellKnownSid(known_sid, null_mut(), admin_sid_ptr, &mut sid_size) == FALSE {
                let err = GetLastError();
                log::debug!(
                    "Error getting wellknown administators sid, GetLastError() : {}",
                    err
                );
                return Err(WinAPIError::LastError(err));
            }
            let mut is_member: BOOL = FALSE;
            if CheckTokenMembership(
                self.h_token,
                admin_sid.as_mut_ptr() as PSID,
                &mut is_member as PBOOL,
            ) == FALSE
            {
                let err = GetLastError();
                log::debug!(
                    "Error checking token's membership to admins group, GetLastError() : {}",
                    err
                );
                return Err(WinAPIError::LastError(err));
            }
            Ok(is_member == TRUE)
        }
    }

    /// Checks if the self token is a member of the builtin Administrator's group
    pub fn is_admin(&self) -> Result<bool, WinAPIError> {
        self.is_member(WinBuiltinAdministratorsSid)
    }

    /// Checks if the token is a limited token sourced from a token with administator's privilege
    pub fn can_elevate(&self) -> Result<bool, WinAPIError> {
        let source = self.source_token()?;

        match source {
            Some(token) => token.is_admin(),
            None => Ok(false),
        }
    }

    // If the token is a limited token, this function will return the sourc token
    pub fn source_token(&self) -> Result<Option<Token>, WinAPIError> {
        unsafe {
            let mut token_info: TOKEN_ELEVATION_TYPE = std::mem::zeroed();
            let token_info_ptr: *mut winapi::ctypes::c_void =
                &mut token_info as *mut _ as *mut winapi::ctypes::c_void;
            let mut returned_length: DWORD = 0u32;
            if GetTokenInformation(
                self.h_token,
                TokenElevationType,
                token_info_ptr,
                std::mem::size_of::<TOKEN_ELEVATION_TYPE>() as u32,
                &mut returned_length,
            ) == FALSE
            {
                let err = GetLastError();
                log::debug!(
                    "Error getting token elevation type information GetLastError: {}",
                    err
                );
                return Err(WinAPIError::LastError(err));
            }

            if token_info == TokenElevationTypeLimited {
                let mut token_linked: TOKEN_LINKED_TOKEN = std::mem::zeroed();
                let token_linked_ptr = &mut token_linked as *mut _ as PVOID;

                let mut returned_length: DWORD = 0u32;
                if GetTokenInformation(
                    self.h_token,
                    TokenLinkedToken,
                    token_linked_ptr,
                    std::mem::size_of::<TOKEN_LINKED_TOKEN>() as u32,
                    &mut returned_length,
                ) == FALSE
                {
                    let err = GetLastError();
                    log::debug!(
                        "Error getting token linked information GetLastError: {}",
                        err
                    );
                    return Err(WinAPIError::LastError(err));
                }
                return Ok(Some(Token {
                    h_token: token_linked.LinkedToken,
                }));
            }
            Ok(None)
        }
    }

    pub fn handle(&self) -> &HANDLE {
        &self.h_token
    }
}
#[cfg(test)]
mod tests {

    use super::*;
    use winapi::um::winnt::{TokenImpersonation, TokenPrimary};
    use winapi::um::winnt::{TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_QUERY_SOURCE};

    pub enum IsAdmin {
        NotAnAdmin,
        Admin,
        CanElevate,
    }

    pub fn is_admin() -> Result<IsAdmin, WinAPIError> {
        let token =
            Token::from_current_process(TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE)?;

        let token = if token.token_type()? == TokenPrimary {
            token.duplicate(TokenImpersonation)?
        } else {
            token
        };

        if !token.is_admin()? {
            if token.can_elevate()? {
                return Ok(IsAdmin::CanElevate);
            } else {
                return Ok(IsAdmin::NotAnAdmin);
            }
        }
        Ok(IsAdmin::Admin)
    }

    #[test]
    fn get_process_token() {
        let _token =
            Token::from_current_process(TOKEN_QUERY).expect("failed to open process token");
    }

    #[test]
    fn get_token_type() {
        let token = Token::from_current_process(TOKEN_QUERY).expect("failed to open process token");

        let token_type = token.token_type().expect("failed to obtain the token type");
        assert!(token_type == TokenImpersonation || token_type == TokenPrimary);
    }

    #[test]
    fn get_token_source() {
        let token = Token::from_current_process(TOKEN_QUERY | TOKEN_QUERY_SOURCE)
            .expect("failed to open process token");

        let _source = token
            .source_token()
            .expect("failed to get information on source token");
    }

    #[test]
    fn test_is_admin() {
        let _is_admin = is_admin().expect("failed to determine if current user is an admin");
    }
}
