use http::Uri;
use serde::{de, Deserializer};
use std::fmt;

struct UriVisitor;
impl<'de> de::Visitor<'de> for UriVisitor {
    type Value = Uri;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "valid uri")
    }

    fn visit_str<E: de::Error>(self, val: &str) -> Result<Self::Value, E> {
        val.parse()
            .map_err(|_| de::Error::invalid_value(de::Unexpected::Str(val), &self))
    }
}

pub fn deserialize<'de, D>(de: D) -> Result<Uri, D::Error>
where
    D: Deserializer<'de>,
{
    de.deserialize_str(UriVisitor)
}
