use crate::auth_scheme::ClientAuthentication;
use crate::errors::{Error, OidcValidationError};
use crate::oidc::Token;
use crate::provider;
use crate::provider::{Claims, Provider, JWKS};
use http::{Request, Response};
use jsonwebtoken::TokenData;
use serde::de::DeserializeOwned;
use std::future::Future;

#[derive(Debug)]
#[non_exhaustive]
pub struct ClientInfoStage {
    pub issuer_domain: String,
    pub auth: ClientAuthentication,
    pub redirect_uri: String,
    pub scopes: Option<Vec<String>>,
}

impl ClientInfoStage {
    pub fn new(
        issuer_domain: String,
        auth: ClientAuthentication,
        redirect_uri: String,
        scopes: Option<Vec<String>>,
    ) -> Self {
        ClientInfoStage {
            issuer_domain,
            auth,
            redirect_uri,
            scopes,
        }
    }

    pub fn generate_provider_request(&self) -> Result<Request<Vec<u8>>, Error> {
        provider::well_known(&self.issuer_domain)
    }

    pub fn validate_provider<S>(self, input: Response<S>) -> Result<AuthorizationStage, Error>
    where
        S: AsRef<[u8]>,
    {
        let provider = Provider::from_response(input)?;
        Ok(AuthorizationStage {
            client_data: self,
            provider,
        })
    }

    pub async fn run_to_end<'a, ReqFn, ReqFut, S, AuthFut, U>(
        self,
        req_fn: ReqFn,
        auth_fut: AuthFut,
    ) -> Result<Finalized<U>, Error>
    where
        ReqFn: Fn(Request<Vec<u8>>) -> ReqFut,
        ReqFut: Future<Output = Response<S>>,
        S: AsRef<[u8]>,
        AuthFut: Future<Output = (String, Option<String>)>,
        U: DeserializeOwned,
    {
        let res = (req_fn)(self.generate_provider_request()?).await;
        let authorization = self.validate_provider(res)?;
        let _res = (req_fn)(authorization.generate_authorization_request()?).await;
        let (auth_code, state) = auth_fut.await;
        let token = authorization.validate_auth_info(auth_code, state.as_deref())?;
        let res = (req_fn)(token.generate_access_token_request()?).await;
        let validate = token.parse_token(res)?;
        let res = (req_fn)(validate.generate_provider_jwks_request()?).await;
        let fetch_user_info = validate.validate_token(res)?;
        let res = (req_fn)(fetch_user_info.generate_fetch_request()?).await;
        fetch_user_info.finalize(res)
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub struct AuthorizationStage {
    pub client_data: ClientInfoStage,
    pub provider: Provider,
}

impl AuthorizationStage {
    pub fn generate_authorization_request(&self) -> Result<Request<Vec<u8>>, Error> {
        self.provider
            .authorization_request(
                &self.client_data.redirect_uri,
                &self.client_data.auth,
                &self.client_data.scopes,
            )
            .map_err(|e| e.into())
    }

    pub fn validate_auth_info(
        self,
        auth_code: String,
        state: Option<&str>,
    ) -> Result<AccessTokenStage, Error> {
        if state != self.client_data.auth.state.as_deref() {
            return Err(crate::errors::Error::OidcValidation(
                OidcValidationError::UserMismatch,
            ));
        }
        Ok(AccessTokenStage {
            client_data: self.client_data,
            provider: self.provider,
            auth_code,
        })
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub struct AccessTokenStage {
    pub client_data: ClientInfoStage,
    pub provider: Provider,
    pub auth_code: String,
}

impl AccessTokenStage {
    pub fn generate_access_token_request(&self) -> Result<Request<Vec<u8>>, Error> {
        self.provider
            .exchange_token_request(
                &self.client_data.redirect_uri,
                &self.client_data.auth,
                &self.auth_code,
            )
            .map_err(|e| e.into())
    }

    pub fn parse_token<S>(self, input: Response<S>) -> Result<TokenValidationStage, Error>
    where
        S: AsRef<[u8]>,
    {
        let token = Token::from_response(input)?;
        Ok(TokenValidationStage {
            client_data: self.client_data,
            provider: self.provider,
            token,
        })
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub struct TokenValidationStage {
    pub client_data: ClientInfoStage,
    pub provider: Provider,
    pub token: Token,
}

impl TokenValidationStage {
    pub fn generate_provider_jwks_request(&self) -> Result<Request<Vec<u8>>, Error> {
        self.provider.jwks_request().map_err(|e| e.into())
    }

    pub fn validate_token<S>(self, input: Response<S>) -> Result<UserInfoStage, Error>
    where
        S: AsRef<[u8]>,
    {
        let jwks = JWKS::from_response(input)?;
        let token_data = self
            .provider
            .validate_token_data(&self.client_data.auth.client_id, &self.token)?;
        if token_data.claims.nonce != self.client_data.auth.nonce {
            return Err(crate::errors::Error::OidcValidation(
                OidcValidationError::NonceMismatch,
            ));
        }
        let sub = token_data.claims.sub.clone();
        self.provider
            .validate_token_signature(&self.token, jwks.keys.as_slice())?;
        Ok(UserInfoStage {
            client_data: self.client_data,
            provider: self.provider,
            token: self.token,
            token_data,
            sub,
        })
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub struct UserInfoStage {
    pub client_data: ClientInfoStage,
    pub provider: Provider,
    pub token: Token,
    pub token_data: TokenData<Claims>,
    pub sub: String,
}

/// Only used to verify subject
#[derive(Debug, serde::Deserialize)]
struct UserInfo {
    pub sub: String,
}

#[derive(Debug)]
pub struct Finalized<U> {
    pub client_data: ClientInfoStage,
    pub provider: Provider,
    pub token: Token,
    pub token_data: TokenData<Claims>,
    pub user_data: U,
}

impl UserInfoStage {
    pub fn generate_fetch_request(&self) -> Result<Request<Vec<u8>>, Error> {
        self.provider
            .user_info_request(&self.token.access_token)
            .map_err(|e| e.into())
    }

    pub fn finalize<S, U: DeserializeOwned>(self, input: Response<S>) -> Result<Finalized<U>, Error>
    where
        S: AsRef<[u8]>,
    {
        let result = input.body().as_ref();
        let raw_user_data = String::from_utf8(result.to_vec())
            .map_err(|_e| Error::OidcValidation(OidcValidationError::UserInfoDecode))?;
        let user_info = serde_json::from_str::<UserInfo>(&raw_user_data)
            .map_err(|_e| Error::OidcValidation(OidcValidationError::UserinfoDeserialize))?;
        if user_info.sub != self.sub {
            Err(Error::OidcValidation(OidcValidationError::UserMismatch))
        } else {
            let user_data = serde_json::from_slice(raw_user_data.as_bytes())?;
            Ok(Finalized {
                client_data: self.client_data,
                provider: self.provider,
                token: self.token,
                token_data: self.token_data,
                user_data,
            })
        }
    }
}
