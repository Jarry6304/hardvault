use crate::error::{HardvaultError, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use zeroize::Zeroize;

/// secrets.toml 的反序列化結構
///
/// 使用 BTreeMap 而非 HashMap，確保產出穩定的 KEY 順序（方便 diff）。
#[derive(Debug, Deserialize, Default)]
pub struct SecretsToml {
    #[serde(default)]
    pub secrets: BTreeMap<String, String>,
    #[serde(default)]
    pub config: BTreeMap<String, String>,
}

impl Zeroize for SecretsToml {
    fn zeroize(&mut self) {
        for v in self.secrets.values_mut() {
            v.zeroize();
        }
        for v in self.config.values_mut() {
            v.zeroize();
        }
    }
}

impl Drop for SecretsToml {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SecretsToml {
    /// 解析並驗證 secrets.toml 文字
    pub fn parse(content: &str) -> Result<Self> {
        let parsed: Self = toml::from_str(content)?;
        parsed.validate()?;
        Ok(parsed)
    }

    /// 驗證 schema 規則
    pub fn validate(&self) -> Result<()> {
        if self.secrets.is_empty() && self.config.is_empty() {
            return Err(HardvaultError::Schema(
                "[secrets] 與 [config] 兩個區段都是空的，至少要有一個 KEY".into(),
            ));
        }

        for k in self.secrets.keys().chain(self.config.keys()) {
            if !is_valid_key_name(k) {
                return Err(HardvaultError::Schema(format!(
                    "KEY '{k}' 不符合命名規範（必須符合 ^[A-Z][A-Z0-9_]*$）"
                )));
            }
        }

        for k in self.secrets.keys() {
            if self.config.contains_key(k) {
                return Err(HardvaultError::Schema(format!(
                    "KEY '{k}' 同時出現在 [secrets] 與 [config]，請擇一"
                )));
            }
        }

        Ok(())
    }
}

/// 驗證 KEY 命名：`^[A-Z][A-Z0-9_]*$`
///
/// 不引 regex crate 以縮小 binary 體積。
fn is_valid_key_name(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_uppercase() {
        return false;
    }
    chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_minimal() {
        let toml = r#"
[secrets]
LINE_TOKEN = "abc"
"#;
        let s = SecretsToml::parse(toml).unwrap();
        assert_eq!(s.secrets.get("LINE_TOKEN").unwrap(), "abc");
        assert!(s.config.is_empty());
    }

    #[test]
    fn parse_both_sections() {
        let toml = r#"
[secrets]
TOKEN = "ey_xxx"

[config]
PAGE_SIZE = "50"
"#;
        let s = SecretsToml::parse(toml).unwrap();
        assert_eq!(s.secrets.len(), 1);
        assert_eq!(s.config.len(), 1);
    }

    #[test]
    fn parse_config_only() {
        let toml = r#"
[config]
PAGE_SIZE = "50"
"#;
        let s = SecretsToml::parse(toml).unwrap();
        assert!(s.secrets.is_empty());
        assert_eq!(s.config.len(), 1);
    }

    #[test]
    fn reject_lowercase_key() {
        let toml = r#"
[secrets]
line_token = "abc"
"#;
        assert!(SecretsToml::parse(toml).is_err());
    }

    #[test]
    fn reject_kebab_case_key() {
        let toml = r#"
[secrets]
"LINE-TOKEN" = "abc"
"#;
        assert!(SecretsToml::parse(toml).is_err());
    }

    #[test]
    fn reject_starts_with_underscore() {
        let toml = r#"
[secrets]
_TOKEN = "abc"
"#;
        assert!(SecretsToml::parse(toml).is_err());
    }

    #[test]
    fn reject_starts_with_digit() {
        let toml = r#"
[secrets]
"1TOKEN" = "abc"
"#;
        assert!(SecretsToml::parse(toml).is_err());
    }

    #[test]
    fn reject_duplicate_key_across_sections() {
        let toml = r#"
[secrets]
DUP = "a"

[config]
DUP = "b"
"#;
        let err = SecretsToml::parse(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("DUP"));
    }

    #[test]
    fn reject_empty() {
        assert!(SecretsToml::parse("").is_err());
    }

    #[test]
    fn reject_only_empty_sections() {
        let toml = r#"
[secrets]
[config]
"#;
        assert!(SecretsToml::parse(toml).is_err());
    }

    #[test]
    fn key_name_validator() {
        assert!(is_valid_key_name("A"));
        assert!(is_valid_key_name("ABC"));
        assert!(is_valid_key_name("A_B_C"));
        assert!(is_valid_key_name("API_KEY_V2"));
        assert!(is_valid_key_name("A1"));

        assert!(!is_valid_key_name(""));
        assert!(!is_valid_key_name("a"));
        assert!(!is_valid_key_name("abc"));
        assert!(!is_valid_key_name("1ABC"));
        assert!(!is_valid_key_name("_ABC"));
        assert!(!is_valid_key_name("A-B"));
        assert!(!is_valid_key_name("A.B"));
        assert!(!is_valid_key_name("Á"));
    }

    #[test]
    fn btreemap_keeps_order() {
        let toml = r#"
[secrets]
B = "2"
A = "1"
C = "3"
"#;
        let s = SecretsToml::parse(toml).unwrap();
        let keys: Vec<_> = s.secrets.keys().collect();
        assert_eq!(keys, vec!["A", "B", "C"]);
    }
}
