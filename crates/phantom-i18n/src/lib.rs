//! Internationalization (i18n) for Phantom Coin
//! Supports 14 languages

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    #[default]
    En,
    De,
    Es,
    Fr,
    It,
    Pt,
    Nl,
    Ru,
    Zh,
    Ja,
    Ko,
    Tr,
    Ar,
    Pl,
}

impl Lang {
    pub fn name(&self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::De => "Deutsch",
            Lang::Es => "Español",
            Lang::Fr => "Français",
            Lang::It => "Italiano",
            Lang::Pt => "Português",
            Lang::Nl => "Nederlands",
            Lang::Ru => "Русский",
            Lang::Zh => "简体中文",
            Lang::Ja => "日本語",
            Lang::Ko => "한국어",
            Lang::Tr => "Türkçe",
            Lang::Ar => "العربية",
            Lang::Pl => "Polski",
        }
    }

    pub fn all() -> &'static [Lang] {
        &[
            Lang::En,
            Lang::De,
            Lang::Es,
            Lang::Fr,
            Lang::It,
            Lang::Pt,
            Lang::Nl,
            Lang::Ru,
            Lang::Zh,
            Lang::Ja,
            Lang::Ko,
            Lang::Tr,
            Lang::Ar,
            Lang::Pl,
        ]
    }
}

impl Lang {
    pub fn from_str(s: &str) -> Self {
        match s {
            "de" => Lang::De,
            "es" => Lang::Es,
            "fr" => Lang::Fr,
            "it" => Lang::It,
            "pt" => Lang::Pt,
            "nl" => Lang::Nl,
            "ru" => Lang::Ru,
            "zh" => Lang::Zh,
            "ja" => Lang::Ja,
            "ko" => Lang::Ko,
            "tr" => Lang::Tr,
            "ar" => Lang::Ar,
            "pl" => Lang::Pl,
            _ => Lang::En,
        }
    }
}

// Common texts used across all components
mod cli;
mod common;
mod dashboard;
mod tui;

pub use cli::*;
pub use common::*;
pub use dashboard::*;
pub use tui::*;
