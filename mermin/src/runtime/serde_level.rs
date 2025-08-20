use serde::{self, Deserialize, Deserializer, Serializer};
use tracing::Level;

pub fn serialize<S>(level: &Level, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(level.as_str())
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Level, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    s.parse::<Level>().map_err(serde::de::Error::custom)
}
