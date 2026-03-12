pub const PRODUCT_NAME: &str = "IX-Operator";
pub const CRATE_NAME: &str = "ix_crypto";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn bootstrap_banner() -> String {
    format!("{PRODUCT_NAME}::{CRATE_NAME} v{VERSION}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_contains_product_name() {
        let banner = bootstrap_banner();
        assert!(banner.contains(PRODUCT_NAME));
    }

    #[test]
    fn banner_contains_crate_name() {
        let banner = bootstrap_banner();
        assert!(banner.contains(CRATE_NAME));
    }
}
