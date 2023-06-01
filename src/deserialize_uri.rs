use http::Uri;
use serde::de::Error;
use serde::{de, Deserializer};
use std::fmt;

pub struct UriVisitor;
impl<'de> de::Visitor<'de> for UriVisitor {
    type Value = Uri;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "valid uri")
    }

    fn visit_str<E: de::Error>(self, val: &str) -> Result<Self::Value, E> {
        val.parse()
            .map_err(|_err| de::Error::invalid_value(de::Unexpected::Str(val), &self))
    }
}

pub struct OptionalUriVisitor;
impl<'de> de::Visitor<'de> for OptionalUriVisitor {
    type Value = Option<Uri>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "valid uri")
    }

    #[inline]
    fn visit_str<E: de::Error>(self, val: &str) -> Result<Self::Value, E> {
        Some(UriVisitor.visit_str(val)).transpose()
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(None)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        Some(deserializer.deserialize_option(UriVisitor)).transpose()
    }
}

pub fn deserialize<'de, D>(de: D) -> Result<Uri, D::Error>
where
    D: Deserializer<'de>,
{
    de.deserialize_str(UriVisitor)
}

pub fn deserialize_opt<'de, D>(de: D) -> Result<Option<Uri>, D::Error>
where
    D: Deserializer<'de>,
{
    de.deserialize_str(OptionalUriVisitor)
}
