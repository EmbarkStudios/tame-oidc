use crate::{
    errors::{RequestError, TokenDataError},
    oidc::into_uri,
};
use http::Uri;
use jsonwebtoken::{decode, Algorithm, DecodingKey, TokenData, Validation};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

#[derive(Deserialize, Debug)]
pub struct Provider {
    pub issuer: String,
    #[serde(with = "crate::deserialize_uri")]
    pub authorization_endpoint: Uri,
    #[serde(with = "crate::deserialize_uri")]
    pub token_endpoint: Uri,
    #[serde(with = "crate::deserialize_uri")]
    pub jwks_uri: Uri,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub claims_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
}

#[derive(serde::Deserialize, Debug)]
pub struct JWK {
    kty: String,
    alg: String,
    #[serde(rename = "e")]
    pub exponent: String,
    kid: String,
    r#use: String,
    // the actual key
    #[serde(rename = "n")]
    pub key: String,
}

#[derive(serde::Deserialize, Debug)]
pub struct JWKS {
    pub keys: Vec<JWK>,
}

pub fn from_str(data: &str) -> Provider {
    serde_json::from_str::<Provider>(&data).unwrap()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
}

/// Deserialize token data
/// Returns either a token or jsonwebtoken error
pub fn token_data(token: &str, jwks: &[JWK]) -> Result<TokenData<Claims>, TokenDataError> {
    let mut error = None;
    for jwk in jwks {
        match try_token_data(token, &jwk) {
            Ok(data) => return Ok(data),
            Err(err) => error = Some(err),
        };
    }
    error
        .map(TokenDataError::JWTDecode)
        .map(Err)
        .unwrap_or(Err(TokenDataError::NoJWKs))
}

fn try_token_data(token: &str, jwk: &JWK) -> jsonwebtoken::errors::Result<TokenData<Claims>> {
    let exponent = &jwk.exponent.to_string();
    let rsa_component = &jwk.key.to_string();
    decode::<Claims>(
        &token,
        &DecodingKey::from_rsa_components(rsa_component.as_str(), exponent.as_str()),
        &Validation::new(Algorithm::RS256),
    )
}

/// Return a Request object for validating a well-known OIDC issuer
pub fn well_known(issuer: &str) -> Result<http::Request<&'static str>, tame_oauth::Error> {
    let well_known_uri = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );

    let request = http::Request::builder()
        .method("GET")
        .uri(&well_known_uri)
        .body("")?;

    Ok(request)
}

/// Return a Request object for fetching a JWKS definition
/// Basically just a HTTP GET function.
pub fn jwks<ReqUri: TryInto<Uri>>(
    uri: ReqUri,
) -> Result<http::Request<&'static str>, RequestError> {
    Ok(http::Request::builder()
        .method("GET")
        .uri(into_uri(uri)?)
        .body("")?)
}

#[cfg(test)]
mod test {

    use http::{Method, Uri};

    use super::*;

    #[test]
    fn well_known_req() {
        let req = well_known("https://issuer.example.com").unwrap();
        assert_eq!(req.method(), Method::GET);
        assert_eq!(
            req.uri(),
            &"https://issuer.example.com/.well-known/openid-configuration"
                .parse::<Uri>()
                .unwrap()
        );
    }
}
