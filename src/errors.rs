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
}
