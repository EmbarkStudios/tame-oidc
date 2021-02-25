use thiserror::Error;

#[derive(Error, Debug)]
pub enum RequestError {
    #[error("The provided Uri was invalid")]
    InvalidUri,

    #[error(transparent)]
    HTTP(#[from] http::Error),
}

#[derive(Error, Debug)]
pub enum TokenDataError {
    #[error("No JWKs provided to decode token")]
    NoJWKs,

    #[error(transparent)]
    JWTDecode(#[from] jsonwebtoken::errors::Error),
}
