#![allow(clippy::unwrap_used)]
use i18n_config::{Crate, I18nConfig, I18nConfigError};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const AGE_CONFIG: &str = include_str!("fixtures/age-i18n.toml");
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/parser-fixtures")
            .join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn file(&self, name: &str, text: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, text).unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn assert_parse_error(text: &str) {
    let fixture = Fixture::new();
    let path = fixture.file("i18n.toml", text);
    match I18nConfig::from_file(&path).unwrap_err() {
        I18nConfigError::CannotDeserializeToml(actual, error) => {
            assert_eq!(actual, path);
            // Typed payload remains a usable standard error; diagnostic wording is parser-specific.
            let _: &dyn std::error::Error = &error;
            assert!(!error.to_string().is_empty());
        }
        error => panic!("unexpected error variant: {:?}", error),
    }
}

#[test]
fn actual_age_macro_configuration_and_crlf() {
    // Git may check out the embedded fixture with CRLF on Windows. Normalize
    // before constructing each encoding so CRLF never becomes CRCRLF.
    let lf = AGE_CONFIG.replace("\r\n", "\n");
    for text in [AGE_CONFIG.to_owned(), lf.clone(), lf.replace('\n', "\r\n")] {
        let fixture = Fixture::new();
        let config = I18nConfig::from_file(fixture.file("i18n.toml", &text)).unwrap();
        assert_eq!(config.fallback_language.to_string(), "en-US");
        assert!(config.subcrates.is_empty());
        assert!(config.gettext.is_none());
        let fluent = config.fluent.unwrap();
        assert_eq!(fluent.assets_dir, PathBuf::from("i18n"));
        assert_eq!(fluent.domain, None);
    }
}

#[test]
fn fluent_domain_and_optional_sections() {
    let fixture = Fixture::new();
    let path = fixture.file("i18n.toml", "fallback_language='it-IT'\nsubcrates=['a','path with spaces']\n[fluent]\nassets_dir='assets/locales'\ndomain='application'\n");
    let config = I18nConfig::from_file(path).unwrap();
    assert_eq!(
        config.subcrates,
        vec![PathBuf::from("a"), PathBuf::from("path with spaces")]
    );
    let fluent = config.fluent.unwrap();
    assert_eq!(fluent.domain.as_deref(), Some("application"));
    assert_eq!(fluent.assets_dir, PathBuf::from("assets/locales"));
    let config =
        I18nConfig::from_file(fixture.file("minimal.toml", "fallback_language='en'\n")).unwrap();
    assert!(config.fluent.is_none() && config.gettext.is_none() && config.subcrates.is_empty());
}

#[test]
fn gettext_default_and_custom_paths() {
    let fixture = Fixture::new();
    let base =
        "fallback_language='en'\n[gettext]\ntarget_languages=['it','de']\noutput_dir='generated'\n";
    let config = I18nConfig::from_file(fixture.file("defaults.toml", base)).unwrap();
    let gettext = config.gettext.unwrap();
    assert_eq!(gettext.target_languages, ["it", "de"]);
    assert_eq!(gettext.pot_dir(), PathBuf::from("generated/pot"));
    assert_eq!(gettext.po_dir(), PathBuf::from("generated/po"));
    assert_eq!(gettext.mo_dir(), PathBuf::from("generated/mo"));
    assert!(
        !gettext.extract_to_parent && !gettext.collate_extracted_subcrates && !gettext.use_fuzzy
    );
    assert_eq!(gettext.add_location.to_str(), "full");
    let custom = format!("{}pot_dir='custom-pot'\npo_dir='custom-po'\nmo_dir='custom-mo'\nextract_to_parent=true\ncollate_extracted_subcrates=true\nuse_fuzzy=true\nadd_location='never'\n", base);
    let gettext = I18nConfig::from_file(fixture.file("custom.toml", &custom))
        .unwrap()
        .gettext
        .unwrap();
    assert_eq!(gettext.pot_dir(), PathBuf::from("custom-pot"));
    assert_eq!(gettext.po_dir(), PathBuf::from("custom-po"));
    assert_eq!(gettext.mo_dir(), PathBuf::from("custom-mo"));
    assert!(gettext.extract_to_parent && gettext.collate_extracted_subcrates && gettext.use_fuzzy);
    assert_eq!(gettext.add_location.to_str(), "never");
}

#[test]
fn malformed_duplicate_and_wrong_types_fail_at_typed_boundary() {
    for text in [
        "fallback_language=",
        "fallback_language='en'\nfallback_language='it'",
        "fallback_language=12",
        "fallback_language='en'\nsubcrates='wrong'",
        "fallback_language='en'\n[fluent]\nassets_dir=7",
        "fallback_language='en'\n[fluent]\nassets_dir='a'\nassets_dir='b'",
        "[fluent]\nassets_dir='i18n'",
        "fallback_language='not_a_locale_!'",
    ] {
        assert_parse_error(text);
    }
}

#[test]
fn missing_and_unreadable_files_remain_io_errors() {
    let fixture = Fixture::new();
    for path in [fixture.0.join("absent.toml"), fixture.0.clone()] {
        match I18nConfig::from_file(&path).unwrap_err() {
            I18nConfigError::CannotReadFile(actual, _, error) => {
                assert_eq!(actual, path);
                assert!(!error.to_string().is_empty());
            }
            error => panic!("unexpected error variant: {:?}", error),
        }
    }
}

#[test]
fn crate_manifest_and_custom_config_path() {
    let fixture = Fixture::new();
    fixture.file(
        "Cargo.toml",
        "[package]\nname='sample-crate'\nversion='0.1.0'\n[dependencies]\nunused='1'\n",
    );
    fixture.file("custom.toml", AGE_CONFIG);
    let krate = Crate::from(&fixture.0, None, "custom.toml").unwrap();
    assert_eq!(krate.name, "sample-crate");
    assert_eq!(krate.version, "0.1.0");
    assert_eq!(krate.module_name(), "sample_crate");
    assert!(krate.config_or_err().is_ok());
    assert_eq!(krate.config_file_path, PathBuf::from("custom.toml"));
    assert!(Crate::from(&fixture.0, None, "absent.toml")
        .unwrap()
        .i18n_config
        .is_none());
}

#[test]
fn malformed_cargo_manifest_retains_path_and_variant() {
    let fixture = Fixture::new();
    let path = fixture.file("Cargo.toml", "[package]\nname=3\nversion='0.1.0'");
    match Crate::from(&fixture.0, None, "i18n.toml").unwrap_err() {
        I18nConfigError::CannotDeserializeToml(actual, _) => assert_eq!(actual, path),
        error => panic!("unexpected error variant: {:?}", error),
    }
}
