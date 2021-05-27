#![allow(dead_code)]
pub mod errorhandling;
pub mod process;
pub mod token;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
