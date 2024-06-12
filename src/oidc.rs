use crate::auth_scheme::{AuthenticationScheme, ClientAuthentication};
use crate::errors::{Error, RequestError};
use data_encoding::BASE64;
use http::header::AUTHORIZATION;
use http::{header::CONTENT_TYPE, Request, Uri};
use std::convert::TryInto;
use std::time::{SystemTime, UNIX_EPOCH};
use url::form_urlencoded::Serializer;

pub fn authorization_request<ReqUri, RedirectUri>(
    uri: ReqUri,
    redirect_uri: RedirectUri,
    auth: &ClientAuthentication,
    scopes: &Option<Vec<String>>,
) -> Result<Request<Vec<u8>>, RequestError>
where
    ReqUri: TryInto<Uri>,
    RedirectUri: TryInto<Uri>,
{
    let request_builder = Request::builder()
        .method("POST")
        .uri(into_uri(uri)?)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded");
    let mut serializer = Serializer::new(String::new());
    serializer.append_pair("redirect_uri", &into_uri(redirect_uri)?.to_string());
    serializer.append_pair("grant_type", "authorization_code");
    serializer.append_pair("response_type", "code");
    serializer.append_pair(
        "scope",
        &scopes
            .as_ref()
            .map_or_else(|| "openid".to_owned(), |s| s.join(" ")),
    );
    if let Some(state) = &auth.state {
        serializer.append_pair("state", state);
    }
    if let Some(nonce) = &auth.nonce {
        serializer.append_pair("nonce", nonce);
    }
    serializer.append_pair("client_id", &auth.client_id);

    let body = match &auth.scheme {
        AuthenticationScheme::Basic(client_credentials) => {
            let basic = BASE64.encode(
                format!("{}:{}", &auth.client_id, client_credentials.client_secret).as_bytes(),
            );
            request_builder
                .header(AUTHORIZATION, format!("Basic {}", basic))
                .body(Vec::from(serializer.finish()))
        }
        AuthenticationScheme::Post(client_credentials) => request_builder.body(Vec::from(
            serializer
                .append_pair("client_secret", &client_credentials.client_secret)
                .finish(),
        )),
        AuthenticationScheme::Pkce(pkce) => request_builder.body(Vec::from(
            serializer
                .append_pair("code_challenge", &pkce.code_challenge)
                .append_pair("code_challenge_method", &pkce.code_challenge_method)
                .finish(),
        )),
    }?;
    Ok(body)
}

/// This is the schema of the server's response.
#[derive(serde::Deserialize, Debug)]
struct TokenExchangeResponse {
    /// The actual token
    access_token: String,
    /// The token type - most often `bearer`
    token_type: String,
    /// The time until the token expires and a new one needs to be requested
    expires_in: Option<i64>,
    /// The scope used for this token - most often `openid`
    scope: String,
    /// A JSON Web Token that contains information about an authentication event
    /// and claims about the authenticated user.
    id_token: Option<String>,
    /// An opaque refresh token. This is returned if the offline_access scope is
    /// granted.
    refresh_token: Option<String>,
}

/// This is the schema of the server's response.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Token {
    /// The actual token
    pub access_token: String,
    /// The token type - most often `bearer`
    pub token_type: String,
    /// The time until the token expires and a new one needs to be requested
    pub expires_in: Option<i64>,
    /// The time until the token expires and a new one needs to be requested
    pub expires_in_timestamp: Option<i64>,
    /// The scope used for this token - most often `openid`
    pub scope: String,
    /// A JSON Web Token that contains information about an authentication event
    /// and claims about the authenticated user.
    pub id_token: Option<String>,
    /// An opaque refresh token. This is returned if the offline_access scope is
    /// granted.
    pub refresh_token: Option<String>,
}

impl Token {
    /// Once a response has been received for a token request, call this
    /// method to deserialize the token and store it in the cache so that
    /// future API requests don't have to retrieve a new token, until it
    /// expires.
    pub fn from_response<S>(response: http::Response<S>) -> Result<Self, Error>
    where
        S: AsRef<[u8]>,
    {
        parse_token_response(response)
    }
}

impl From<TokenExchangeResponse> for Token {
    fn from(t: TokenExchangeResponse) -> Token {
        let expires_ts = t.expires_in.and_then(|time_until| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH) // Only an err if time moved backwards
                .ok()
                .and_then(|time_stamp| time_stamp.as_secs().try_into().ok()) // Only an err after year 2264
                .map(|now_as_seconds: i64| time_until + now_as_seconds)
        });

        Token {
            access_token: t.access_token,
            token_type: t.token_type,
            refresh_token: t.refresh_token,
            expires_in: t.expires_in,
            expires_in_timestamp: expires_ts,
            scope: t.scope,
            id_token: t.id_token,
        }
    }
}

/// Construct a token exchange request object
/// For [PKCE flow](https://tools.ietf.org/html/rfc7636#section-4.1) pass in the `code_verifier`
/// and omit the `client_secret`.
///
/// For [authorization code flow](https://auth0.com/docs/flows/authorization-code-flow) pass in
/// `client_secret` and omit `code_verifier`.
///
/// Also supports edge cases where i.e. a development machine requires both
/// `client_secret` and `code_verifier`. Just pass in them both in such case.
pub fn exchange_token_request<ReqUri, RedirectUri>(
    uri: ReqUri,
    redirect_uri: RedirectUri,
    auth: &ClientAuthentication,
    auth_code: &str,
) -> Result<Request<Vec<u8>>, RequestError>
where
    ReqUri: TryInto<Uri>,
    RedirectUri: TryInto<Uri>,
{
    let mut serializer = Serializer::new(String::new());
    let mut redir = &mut into_uri(redirect_uri)?.to_string();
    redir.pop();
    serializer.append_pair("redirect_uri", redir);
    serializer.append_pair("grant_type", "authorization_code");
    serializer.append_pair("code", auth_code);
    let request_builder = Request::builder()
        .method("POST")
        .uri(into_uri(uri)?)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded");
    serializer.append_pair("client_id", &auth.client_id);
    let body = match &auth.scheme {
        AuthenticationScheme::Basic(client_credentials) => {
            let basic = BASE64.encode(
                format!("{}:{}", &auth.client_id, client_credentials.client_secret).as_bytes(),
            );
            request_builder
                .header(AUTHORIZATION, format!("Basic {}", basic))
                .body(Vec::from(serializer.finish()))
        }
        AuthenticationScheme::Post(client_credentials) => request_builder.body(Vec::from(
            serializer
                .append_pair("client_secret", &client_credentials.client_secret)
                .finish(),
        )),
        AuthenticationScheme::Pkce(pkce) => {
            if let Some(client_secret) = &pkce.client_secret {
                serializer.append_pair("client_secret", client_secret);
            }
            request_builder.body(Vec::from(
                serializer
                    .append_pair("code_verifier", &pkce.code_verifier)
                    .finish(),
            ))
        }
    }?;
    Ok(body)
}

pub(crate) fn into_uri<U: TryInto<Uri>>(uri: U) -> Result<Uri, RequestError> {
    uri.try_into().map_err(|_err| RequestError::InvalidUri)
}

pub(crate) fn user_info_request<ReqUri>(
    uri: ReqUri,
    access_token: &str,
) -> Result<Request<Vec<u8>>, RequestError>
where
    ReqUri: TryInto<Uri>,
{
    Ok(Request::get(into_uri(uri)?)
        .header(AUTHORIZATION, format!("Bearer {}", access_token))
        .body(vec![])?)
}

/// Once a response has been received for a token request, call this
/// method to deserialize the token and store it in the cache so that
/// future API requests don't have to retrieve a new token, until it
/// expires.
pub fn parse_token_response<S>(response: http::Response<S>) -> Result<Token, Error>
where
    S: AsRef<[u8]>,
{
    let (parts, body) = response.into_parts();

    if !parts.status.is_success() {
        println!("{:?}", core::str::from_utf8(body.as_ref()));
        return Err(Error::HttpStatus(parts.status));
    }

    let token_res: TokenExchangeResponse = serde_json::from_slice(body.as_ref())?;
    let token: Token = token_res.into();

    Ok(token)
}

pub fn refresh_token_request<ReqUri>(
    uri: ReqUri,
    auth: &ClientAuthentication,
    refresh_token: &str,
) -> Result<Request<Vec<u8>>, RequestError>
where
    ReqUri: TryInto<Uri>,
{
    let mut partial = Serializer::new(String::new());
    partial.append_pair("grant_type", "refresh_token");
    partial.append_pair("refresh_token", refresh_token);
    let request_builder = Request::builder()
        .method("POST")
        .uri(into_uri(uri)?)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded");
    partial.append_pair("client_id", &auth.client_id);
    let body = match &auth.scheme {
        AuthenticationScheme::Basic(client_credentials) => {
            let basic = BASE64.encode(
                format!("{}:{}", &auth.client_id, client_credentials.client_secret).as_bytes(),
            );
            request_builder
                .header(AUTHORIZATION, format!("Basic {}", basic))
                .body(Vec::from(partial.finish()))
        }
        AuthenticationScheme::Post(client_credentials) => request_builder.body(Vec::from(
            partial
                .append_pair("client_secret", &client_credentials.client_secret)
                .finish(),
        )),
        AuthenticationScheme::Pkce(pkce) => {
            if let Some(client_secret) = &pkce.client_secret {
                partial.append_pair("client_secret", client_secret);
            }
            request_builder.body(Vec::from(
                partial
                    .append_pair("access_type", "offline")
                    .finish(),
            ))
            /*
            request_builder.body(Vec::from(
                partial
                    .finish(),
            ))

             */
        }
    }?;
    Ok(body)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::auth_scheme::PkceCredentials;
    use std::str;

    #[test]
    fn pkce_flow_exchange() {
        let spooky_secret_verifier = "the_secret_verifier".to_owned();
        let client_credentials = ClientAuthentication::new(
            "client_id".to_owned(),
            AuthenticationScheme::Pkce(PkceCredentials::new(
                "ch".to_owned(),
                "&S256".to_owned(),
                spooky_secret_verifier,
                None,
            )),
            None,
            None,
        );
        let request = exchange_token_request(
            "https://www.example.com/",
            "http://localhost:8000/",
            &client_credentials,
            "auth-code",
        )
        .unwrap();

        let body = str::from_utf8(request.body()).unwrap();

        // should not have client_secret parameter
        assert!(!body.contains("client_secret"));
        assert!(body.contains("code_verifier"));
    }
}
