use crate::util::Threading;
use thiserror::Error;
use zeroize::Zeroizing;

mod serde_opt_zeroizing_bytes32 {
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S>(
        value: &Option<Zeroizing<[u8; 32]>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(k) => serializer.serialize_some(&**k),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Zeroizing<[u8; 32]>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<[u8; 32]>::deserialize(deserializer)?;
        Ok(opt.map(Zeroizing::new))
    }
}

#[derive(Error, Debug)]
#[error("{0}")]
pub struct ConfigError(pub String);

#[derive(Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct NoiseConfigData {
    // We still need serde support, but also want the private key to be
    // zeroized when dropped.
    #[serde(default, with = "serde_opt_zeroizing_bytes32")]
    pub app_static_privkey: Option<Zeroizing<[u8; 32]>>,
    pub device_static_pubkeys: Vec<Vec<u8>>,
}

impl std::fmt::Debug for NoiseConfigData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let app_static_privkey = self.app_static_privkey.as_ref().map(|_| "<redacted>");
        f.debug_struct("NoiseConfigData")
            .field("app_static_privkey", &app_static_privkey)
            .field("device_static_pubkeys", &self.device_static_pubkeys)
            .finish()
    }
}

impl NoiseConfigData {
    pub(crate) fn contains_device_static_pubkey(&self, pubkey: &[u8]) -> bool {
        self.device_static_pubkeys
            .iter()
            .any(|config_pubkey| config_pubkey.as_slice() == pubkey)
    }

    pub(crate) fn add_device_static_pubkey(&mut self, pubkey: &[u8]) {
        if !self.contains_device_static_pubkey(pubkey) {
            self.device_static_pubkeys.push(pubkey.to_vec());
        }
    }

    pub(crate) fn get_app_static_privkey(&self) -> Option<Zeroizing<[u8; 32]>> {
        self.app_static_privkey.clone()
    }

    pub(crate) fn set_app_static_privkey(&mut self, privkey: &[u8]) -> Result<(), ConfigError> {
        // Drop + zeroize any existing key first.
        self.app_static_privkey.take();

        self.app_static_privkey =
            Some(Zeroizing::new(privkey.try_into().map_err(
                |e: std::array::TryFromSliceError| ConfigError(e.to_string()),
            )?));
        Ok(())
    }
}

pub trait NoiseConfig: Threading {
    fn read_config(&self) -> Result<NoiseConfigData, ConfigError> {
        Ok(NoiseConfigData::default())
    }
    fn store_config(&self, _conf: &NoiseConfigData) -> Result<(), ConfigError> {
        Ok(())
    }
}

pub struct NoiseConfigNoCache;
impl NoiseConfig for NoiseConfigNoCache {}
impl Threading for NoiseConfigNoCache {}

pub struct PersistedNoiseConfig {
    config_dir: String,
}

impl Threading for PersistedNoiseConfig {}

impl PersistedNoiseConfig {
    /// Creates a new persisting noise config, which stores the pairing information in "bitbox.json"
    /// in the provided directory.
    pub fn new(config_dir: &str) -> PersistedNoiseConfig {
        PersistedNoiseConfig {
            config_dir: config_dir.into(),
        }
    }
}

impl NoiseConfig for PersistedNoiseConfig {
    fn read_config(&self) -> Result<NoiseConfigData, ConfigError> {
        use std::io::Read;

        let config_path = std::path::Path::new(&self.config_dir).join("bitbox.json");

        if !config_path.exists() {
            return Ok(NoiseConfigData::default());
        }

        let mut file = std::fs::File::open(config_path).map_err(|e| ConfigError(e.to_string()))?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| ConfigError(e.to_string()))?;

        serde_json::from_str::<NoiseConfigData>(&contents).map_err(|e| ConfigError(e.to_string()))
    }

    fn store_config(&self, conf: &NoiseConfigData) -> Result<(), ConfigError> {
        use std::io::Write;

        let config_path = std::path::Path::new(&self.config_dir).join("bitbox.json");

        let mut file =
            std::fs::File::create(config_path).map_err(|e| ConfigError(e.to_string()))?;

        let data = serde_json::to_string(conf).map_err(|e| ConfigError(e.to_string()))?;

        file.write_all(data.as_bytes())
            .map_err(|e| ConfigError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f71_noise_configdata_privkey_is_zeroizing_and_debug_redacts() {
        let mut cfg = NoiseConfigData::default();
        let key = [7u8; 32];
        cfg.set_app_static_privkey(&key).expect("set key");

        // Debug must not leak the key bytes.
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("0707"));

        // Serde roundtrip keeps the key bytes (while still being zeroized on drop).
        let ser = serde_json::to_string(&cfg).expect("serialize");
        let de: NoiseConfigData = serde_json::from_str(&ser).expect("deserialize");
        let got = de.get_app_static_privkey().expect("privkey present");
        assert_eq!(&*got, &key);
    }
}

// (no additional tests)
