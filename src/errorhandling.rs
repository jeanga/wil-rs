#[derive(Debug)]
pub enum WinAPIError {
    _HRESULT(u32),
    LastError(u32),
}
