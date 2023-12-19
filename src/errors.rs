#[derive(thiserror::Error, Debug)]
#[allow(clippy::upper_case_acronyms)]
pub enum RequestError {
    #[error("The provided Uri was invalid")]
    InvalidUri,

    #[error(transparent)]
    HTTP(#[from] http::Error),
}

#[derive(thiserror::Error, Debug)]
#[allow(clippy::upper_case_acronyms)]
pub enum TokenDataError {
    #[error("No JWKs provided to decode token")]
    NoJWKs,

    #[error(transparent)]
    JWTDecode(#[from] jsonwebtoken::errors::Error),
}

#[derive(thiserror::Error, Debug)]
#[allow(clippy::upper_case_acronyms)]
pub enum OidcValidationError {
    #[error("Nonce doesn't match initially provided nonce")]
    NonceMismatch,

    #[error("Provider did not contain a userinfo endpoint")]
    NoUserEndpoint,

    #[error("Sub from user data doesn't match sub from token data")]
    UserMismatch,

    #[error("Could not decode user info as utf8")]
    UserInfoDecode,

    #[error("Could not deserialize user info")]
    UserinfoDeserialize,

    #[error("State doesn't match initially provided state")]
    StateMismatch,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Failed to authenticate and retrieve an oauth token, and were unable to
    /// deserialize a more exact reason from the error response
    #[error("{}", _0)]
    HttpStatus(http::StatusCode),
    /// Failed to de/serialize JSON
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// An error occurred trying to create an HTTP request
    #[error(transparent)]
    Http(#[from] http::Error),

    #[error(transparent)]
    Request(#[from] RequestError),

    #[error(transparent)]
    TokenValidation(#[from] TokenDataError),

    #[error(transparent)]
    // Todo: Better name
    OidcValidation(#[from] OidcValidationError),
}
