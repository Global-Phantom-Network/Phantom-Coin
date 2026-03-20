// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use pc_consensus::role_policy::RolePolicy;
use pc_consensus::stake_registry::StakeRegistry;
use pc_consensus::validator_control::ValidatorControl;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const ROLE_POLICY_FILENAME: &str = "role_policy.json";
pub const STAKE_REGISTRY_FILENAME: &str = "stake_registry.json";
pub const VALIDATOR_CONTROL_FILENAME: &str = "validator_control.json";

pub fn secs_since_epoch(t: SystemTime) -> Result<u64, String> {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| format!("system clock before UNIX_EPOCH: {e}"))
}

pub fn now_secs() -> Result<u64, String> {
    secs_since_epoch(SystemTime::now())
}

pub fn load_role_policy_from_file(path: &Path) -> Result<RolePolicy, String> {
    let data =
        std::fs::read(path).map_err(|e| format!("read role_policy '{}': {e}", path.display()))?;
    RolePolicy::from_json_bytes(&data)
}

pub fn load_stake_registry_from_file(path: &Path) -> Result<StakeRegistry, String> {
    if !path.exists() {
        return Ok(StakeRegistry::new());
    }
    let data =
        std::fs::read_to_string(path).map_err(|e| format!("read stake_registry.json: {e}"))?;
    StakeRegistry::from_json_str(&data)
}

pub fn save_stake_registry_to_file(reg: &StakeRegistry, path: &Path) -> Result<(), String> {
    let data = reg.to_json_pretty()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create dir {}: {e}", parent.display()))?;
    }
    std::fs::write(path, data).map_err(|e| format!("write stake_registry.json: {e}"))?;
    Ok(())
}

pub fn default_validator_control_fail_closed() -> Result<ValidatorControl, String> {
    Ok(ValidatorControl::default_fail_closed_at(now_secs()?))
}

pub fn load_validator_control_from_file(path: &Path) -> Result<ValidatorControl, String> {
    let data = std::fs::read(path)
        .map_err(|e| format!("read validator_control '{}': {e}", path.display()))?;
    ValidatorControl::from_json_bytes(&data)
}

pub fn save_validator_control_to_file(ctrl: &ValidatorControl, path: &Path) -> Result<(), String> {
    let data = ctrl.to_json_pretty()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create dir {}: {e}", parent.display()))?;
    }
    std::fs::write(path, data)
        .map_err(|e| format!("write validator_control '{}': {e}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn f55_secs_since_epoch_rejects_pre_epoch() {
        let t = UNIX_EPOCH
            .checked_sub(Duration::from_secs(1))
            .expect("SystemTime supports pre-epoch values");
        assert!(secs_since_epoch(t).is_err());
    }
}
