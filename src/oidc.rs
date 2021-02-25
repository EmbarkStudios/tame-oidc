use crate::errors::RequestError;
use http::{header::CONTENT_TYPE, Request, Uri};
use std::convert::TryInto;
use tame_oauth::Error;
use url::form_urlencoded::Serializer;

/// This is the schema of the server's response.
#[derive(serde::Deserialize, Debug)]
struct TokenResponse {
    /// The actual token
    access_token: String,
    /// The token type - most often `bearer`
    token_type: String,
    /// The time until the token expires and a new one needs to be requested
    expires_in: i64,
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
#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    /// The actual token
    pub access_token: String,
    /// The token type - most often `bearer`
    pub token_type: String,
    /// The time until the token expires and a new one needs to be requested
    pub expires_in: i64,
    /// The time until the token expires and a new one needs to be requested
    pub expires_in_timestamp: i64,
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

impl Into<Token> for TokenResponse {
    fn into(self) -> Token {
        let expires_ts = chrono::Utc::now().timestamp() + self.expires_in;

        Token {
            access_token: self.access_token,
            token_type: self.token_type,
            refresh_token: self.refresh_token,
            expires_in: self.expires_in,
            expires_in_timestamp: expires_ts,
            scope: self.scope,
            id_token: self.id_token,
        }
    }
}

pub fn exchange_token_request<ReqUri, RedirectUri>(
    uri: ReqUri,
    redirect_uri: RedirectUri,
    client_id: &str,
    client_secret: &str,
    auth_code: &str,
) -> Result<Request<Vec<u8>>, RequestError>
where
    ReqUri: TryInto<Uri>,
    RedirectUri: TryInto<Uri>,
{
    let body = Serializer::new(String::new())
        .append_pair("client_id", client_id)
        .append_pair("client_secret", client_secret)
        .append_pair("redirect_uri", &into_uri(redirect_uri)?.to_string())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", auth_code)
        .finish();

    let req_body = Vec::from(body);
    Ok(Request::builder()
        .method("POST")
        .uri(into_uri(uri)?)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(req_body)?)
}

pub(crate) fn into_uri<U: TryInto<Uri>>(uri: U) -> Result<Uri, RequestError> {
    uri.try_into().map_err(|_| RequestError::InvalidUri)
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
        return Err(Error::HttpStatus(parts.status));
    }

    let token_res: TokenResponse = serde_json::from_slice(body.as_ref())?;
    let token: Token = token_res.into();

    Ok(token)
}

pub fn refresh_token_request<ReqUri>(
    uri: ReqUri,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> Result<Request<Vec<u8>>, RequestError>
where
    ReqUri: TryInto<Uri>,
{
    let body = Serializer::new(String::new())
        .append_pair("client_id", client_id)
        .append_pair("client_secret", client_secret)
        .append_pair("grant_type", "refresh_token")
        .append_pair("refresh_token", refresh_token)
        .finish();

    let req_body = Vec::from(body);
    Ok(Request::builder()
        .method("POST")
        .uri(into_uri(uri)?)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(req_body)?)
}
