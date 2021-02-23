use jsonwebtoken::{decode, Algorithm, DecodingKey, TokenData, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(serde::Deserialize, Debug)]
pub struct Provider {
    issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    scopes_supported: Vec<String>,
    response_types_supported: Vec<String>,
    claims_supported: Vec<String>,
    grant_types_supported: Vec<String>,
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

#[derive(Error, Debug)]
pub enum TokenDataError {
    #[error("No JWKs provided to decode token")]
    NoJWKs,

    #[error(transparent)]
    JWTDecode(#[from] jsonwebtoken::errors::Error),
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
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body("")?;

    Ok(request)
}

///
/// Return a Request object for fetching a JWKS definition
/// Basically just a HTTP GET function.
pub fn jwks(uri: &str) -> http::Request<&'static str> {
    http::Request::builder()
        .method("GET")
        .uri(uri)
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body("")
        .unwrap()
}

#[cfg(test)]
mod test {

    // TODO: test!
    #[test]
    fn well_known() {}
}
