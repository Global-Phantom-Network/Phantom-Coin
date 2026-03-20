// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorControl {
    pub version: u8,
    /// Hard kill switch: forces voting off.
    pub kill_switch: bool,
    /// Maintenance mode: voting off, node stays online.
    pub maintenance: bool,
    /// Manual disable flag (operator controlled).
    pub manual_disable: bool,
    /// Auto re-enable when conditions are OK.
    pub auto_reenable: bool,
    /// Optional reason for last change.
    #[serde(default)]
    pub reason: String,
    /// Unix timestamp (seconds) of last update.
    pub updated_at: u64,
    /// Optional cooldown end timestamp (seconds).
    #[serde(default)]
    pub cooldown_until: u64,
    /// Optional actor label (gui/cli/node).
    #[serde(default)]
    pub last_changed_by: String,
}

impl ValidatorControl {
    pub fn default_fail_closed_at(updated_at: u64) -> Self {
        Self {
            version: 1,
            kill_switch: false,
            maintenance: false,
            manual_disable: true,
            auto_reenable: false,
            reason: "auto-created: voting disabled until configured".to_string(),
            updated_at,
            cooldown_until: 0,
            last_changed_by: "system".to_string(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err(format!(
                "unsupported validator_control version: {}",
                self.version
            ));
        }
        Ok(())
    }

    pub fn from_json_bytes(data: &[u8]) -> Result<Self, String> {
        let v: ValidatorControl =
            serde_json::from_slice(data).map_err(|e| format!("parse validator_control: {e}"))?;
        v.validate()?;
        Ok(v)
    }

    pub fn to_json_pretty(&self) -> Result<String, String> {
        self.validate()?;
        serde_json::to_string_pretty(self).map_err(|e| format!("serialize validator_control: {e}"))
    }
}
