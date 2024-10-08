use crate::auth_scheme::ClientAuthentication;
use crate::oidc::{authorization_request, user_info_request, Token};
use crate::{
    errors::{Error, RequestError, TokenDataError},
    oidc::{exchange_token_request, into_uri, refresh_token_request},
};
use http::{Request, Uri};
use jsonwebtoken::{decode, Algorithm, DecodingKey, TokenData, Validation};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fmt::Display;

#[derive(Deserialize, Debug)]
pub struct Provider {
    pub issuer: String,
    #[serde(with = "crate::deserialize_uri")]
    pub authorization_endpoint: Uri,
    #[serde(with = "crate::deserialize_uri")]
    pub token_endpoint: Uri,
    #[serde(with = "crate::deserialize_uri")]
    pub jwks_uri: Uri,
    #[serde(default, deserialize_with = "crate::deserialize_uri::deserialize_opt")]
    pub userinfo_endpoint: Option<Uri>,
    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub claims_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
}

impl Provider {
    pub fn from_response<S>(response: http::Response<S>) -> Result<Self, Error>
    where
        S: AsRef<[u8]>,
    {
        let (parts, body) = response.into_parts();
        if !parts.status.is_success() {
            return Err(Error::HttpStatus(parts.status));
        }

        Ok(serde_json::from_slice(body.as_ref())?)
    }

    pub fn authorization_request<RedirectUri>(
        &self,
        redirect_uri: RedirectUri,
        auth: &ClientAuthentication,
        scopes: &Option<Vec<String>>,
    ) -> Result<Request<Vec<u8>>, RequestError>
    where
        RedirectUri: TryInto<Uri> + Display,
    {
        authorization_request(&self.authorization_endpoint, redirect_uri, auth, scopes)
    }

    pub fn exchange_token_request<RedirectUri>(
        &self,
        redirect_uri: RedirectUri,
        auth: &ClientAuthentication,
        auth_code: &str,
    ) -> Result<Request<Vec<u8>>, RequestError>
    where
        RedirectUri: TryInto<Uri> + Display,
    {
        exchange_token_request(&self.token_endpoint, redirect_uri, auth, auth_code)
    }

    // Only used to provide better error messages, otherwise anything comes back as an invalid
    // signature, now we can get f.e. InvalidIssuer specifically
    pub(crate) fn validate_token_data(
        &self,
        client_id: &str,
        token: &Token,
    ) -> Result<TokenData<Claims>, TokenDataError> {
        if let Some(ref id_token) = token.id_token {
            let mut validation = Validation::default();
            validation.set_issuer(&[self.issuer.clone()]);
            validation.set_audience(&[client_id]);
            validation.algorithms = vec![Algorithm::RS256, Algorithm::RS384, Algorithm::RS512];
            validation.insecure_disable_signature_validation();

            return Ok(jsonwebtoken::decode(
                id_token,
                &DecodingKey::from_rsa_raw_components(&[], &[]),
                &validation,
            )?);
        }
        Err(TokenDataError::NoJWKs)
    }

    pub fn validate_token_signature(
        &self,
        client_id: &str,
        token: &Token,
        jwks: &[JWK],
    ) -> Result<TokenData<Claims>, TokenDataError> {
        if let Some(ref id_token) = token.id_token {
            let mut validation = Validation::default();
            validation.set_issuer(&[self.issuer.clone()]);
            validation.set_audience(&[client_id]);
            validation.algorithms = vec![Algorithm::RS256, Algorithm::RS384, Algorithm::RS512];
            validation.set_required_spec_claims(&["iss", "aud", "sub"]);
            return verify_rsa(id_token, jwks, validation);
        }
        Err(TokenDataError::NoJWKs)
    }

    pub fn refresh_token_request(
        &self,
        auth: &ClientAuthentication,
        refresh_token: &str,
    ) -> Result<Request<Vec<u8>>, RequestError> {
        refresh_token_request(&self.token_endpoint, auth, refresh_token)
    }

    pub fn user_info_request(
        &self,
        access_token: &str,
    ) -> Option<Result<Request<Vec<u8>>, RequestError>> {
        self.userinfo_endpoint
            .as_ref()
            .map(|uri| user_info_request(uri, access_token))
    }

    pub fn jwks_request(&self) -> Result<Request<Vec<u8>>, RequestError> {
        jwks(&self.jwks_uri)
    }
}

#[derive(serde::Deserialize, Debug, Clone)]
#[allow(clippy::upper_case_acronyms)]
#[serde(untagged)]
pub enum JWK {
    RSA(RsaJwk),
    EllipticCurve(ECKey),
    OctetKeyPair(OKP),
}

#[derive(serde::Deserialize, Debug, Clone)]
#[allow(dead_code)]
pub struct RsaJwk {
    #[serde(rename = "alg")]
    algorithm: Option<String>,
    #[serde(rename = "kty")]
    key_type: String,
    // TODO: Allow missing kid? Spec is permissive
    #[serde(rename = "kid")]
    key_id: Option<String>,
    r#use: String,
    #[serde(rename = "e")]
    pub exponent: String,
    // the actual key
    #[serde(rename = "n")]
    pub key: String,
}

#[derive(serde::Deserialize, Debug, Clone)]
#[allow(dead_code)]
pub struct ECKey {
    #[serde(rename = "alg")]
    algorithm: Option<String>,
    #[serde(rename = "kty")]
    key_type: String,
    #[serde(rename = "kid")]
    key_id: Option<String>,
    r#use: String,
    #[serde(rename = "crv")]
    pub curve: String,
    pub x: String,
    pub y: String,
}

#[derive(serde::Deserialize, Debug, Clone)]
#[allow(dead_code)]
pub struct OKP {
    #[serde(rename = "kty")]
    key_type: String,
    #[serde(rename = "kid")]
    key_id: Option<String>,
    r#use: String,
    #[serde(rename = "crv")]
    pub curve: String,
    pub x: String,
}

#[derive(serde::Deserialize, Debug, Clone)]
#[allow(clippy::upper_case_acronyms)]
pub struct JWKS {
    pub keys: Vec<JWK>,
}

#[allow(clippy::upper_case_acronyms)]
impl JWKS {
    pub fn from_response<S>(response: http::Response<S>) -> Result<Self, Error>
    where
        S: AsRef<[u8]>,
    {
        let (parts, body) = response.into_parts();
        if !parts.status.is_success() {
            return Err(Error::HttpStatus(parts.status));
        }
        Ok(serde_json::from_slice(body.as_ref())?)
    }
}

#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    // issued at, seconds
    pub iat: u64,
    pub nonce: Option<String>,
}

/// Deserialize token data
/// Returns either a token or jsonwebtoken error
pub fn verify_token<CLAIMS>(token: &str, jwks: &[JWK]) -> Result<TokenData<CLAIMS>, TokenDataError>
where
    CLAIMS: DeserializeOwned,
{
    let mut error = None;
    for jwk in jwks {
        if let JWK::RSA(enc_key) = jwk {
            match try_token_data(token, enc_key) {
                Ok(data) => return Ok(data),
                Err(err) => error = Some(err),
            }
        }
    }
    error
        .map(TokenDataError::JWTDecode)
        .map_or(Err(TokenDataError::NoJWKs), Err)
}

fn try_token_data<CLAIMS>(
    token: &str,
    enc_key: &RsaJwk,
) -> jsonwebtoken::errors::Result<TokenData<CLAIMS>>
where
    CLAIMS: DeserializeOwned,
{
    let mut validation = Validation::default();
    validation.algorithms = vec![Algorithm::RS256, Algorithm::RS384, Algorithm::RS512];
    validation.validate_aud = false;

    decode::<CLAIMS>(
        token,
        &DecodingKey::from_rsa_components(&enc_key.key, &enc_key.exponent)?,
        &validation,
    )
}

pub fn verify_rsa<CLAIMS>(
    token: &str,
    jwks: &[JWK],
    validation: Validation,
) -> Result<TokenData<CLAIMS>, TokenDataError>
where
    CLAIMS: DeserializeOwned,
{
    let mut error = None;
    for jwk in jwks {
        if let JWK::RSA(rsa) = jwk {
            match try_token_rsa_data(token, &rsa.key, &rsa.exponent, &validation) {
                Ok(data) => return Ok(data),
                Err(err) => error = Some(err),
            }
        }
    }
    error
        .map(TokenDataError::JWTDecode)
        .map_or(Err(TokenDataError::NoJWKs), Err)
}

fn try_token_rsa_data<CLAIMS>(
    token: &str,
    key: &str,
    exponent: &str,
    validation: &Validation,
) -> jsonwebtoken::errors::Result<TokenData<CLAIMS>>
where
    CLAIMS: DeserializeOwned,
{
    decode::<CLAIMS>(
        token,
        &DecodingKey::from_rsa_components(key, exponent)?,
        validation,
    )
}
/// Return a Request object for validating a well-known OIDC issuer
pub fn well_known(issuer: &str) -> Result<http::Request<Vec<u8>>, Error> {
    let well_known_uri = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );

    let request = http::Request::builder()
        .method("GET")
        .uri(&well_known_uri)
        .body(Vec::with_capacity(0))?;

    Ok(request)
}

/// Return a Request object for fetching a JWKS definition
/// Basically just a HTTP GET function.
pub fn jwks<ReqUri: TryInto<Uri>>(uri: ReqUri) -> Result<http::Request<Vec<u8>>, RequestError> {
    Ok(http::Request::builder()
        .method("GET")
        .uri(into_uri(uri)?)
        .body(Vec::with_capacity(0))?)
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
