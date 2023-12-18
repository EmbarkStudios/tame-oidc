use http::Uri;
use serde::de::Error;
use serde::{de, Deserializer};
use std::fmt;
use std::fmt::Formatter;

struct UriVisitor;
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

pub fn deserialize<'de, D>(de: D) -> Result<Uri, D::Error>
where
    D: Deserializer<'de>,
{
    de.deserialize_str(UriVisitor)
}

struct OptUriVisitor;

impl<'de> de::Visitor<'de> for OptUriVisitor {
    type Value = Option<Uri>;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "valid or missing uri")
    }

    #[inline]
    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(Some(UriVisitor.visit_str(v)?))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(None)
    }
}

pub fn deserialize_opt<'de, D>(de: D) -> Result<Option<Uri>, D::Error>
where
    D: Deserializer<'de>,
{
    de.deserialize_str(OptUriVisitor)
}
