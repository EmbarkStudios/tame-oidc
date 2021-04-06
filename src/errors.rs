use thiserror::Error;

#[derive(Error, Debug)]
#[allow(clippy::upper_case_acronyms)]
pub enum RequestError {
    #[error("The provided Uri was invalid")]
    InvalidUri,

    #[error(transparent)]
    HTTP(#[from] http::Error),
}

#[derive(Error, Debug)]
#[allow(clippy::upper_case_acronyms)]
pub enum TokenDataError {
    #[error("No JWKs provided to decode token")]
    NoJWKs,

    #[error(transparent)]
    JWTDecode(#[from] jsonwebtoken::errors::Error),
}
