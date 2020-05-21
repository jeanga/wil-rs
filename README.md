# wil-rs
Windows Implementation Library for Rust

[Documentation](https://docs.rs/winapi/)

This crate does _not_ provide raw FFI bindings to Windows API (the winapi crate is what you are looking for).
This crate does demonstrate what a Windows Implementation Library could look like in Rust ("à la" https://github.com/microsoft/wil in C++).

The winapi crate is doing a great job in providing the bindings for Windows APIs.
What winapi does _not_ provide is a safety wrapper arroung those APIs (with error handling, resource management, ...).

This "wil" crate aims to present what could be a safe wrapper for Windows API.

If this crate is massively missing _that_ something you need.
Feel free to create an issue, open a pull request.

## Frequently asked questions ##


## Example ##

This example is not correct... (yet)

Cargo.toml:
```toml
[target.'cfg(windows)'.dependencies]
wil = { version = "0.0.1" }
```
main.rs:
```Rust

fn main() -> Result<(), {

    let token =
        Token::from_current_process(TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE)?;

    let token = if token.token_type()? == TokenPrimary {
        token.duplicate(TokenImpersonation)?
    } else {
        token
    };

    if !token.is_admin()? {
        if token.can_elevate()? {
            println!("user is not an admin but can elevate to one");
        } else {
            println!("user is not an admin");
        }
    }
    else {

    }
}

```
