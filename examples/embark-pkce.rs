#![allow(clippy::dbg_macro)]

use bytes::Bytes;
use http::Request;
use rand::rngs::ThreadRng;
use rand::RngCore;
use reqwest::Url;
use std::{
    convert::TryInto,
    io::{prelude::*, BufReader},
    net::{TcpListener, TcpStream},
    str,
};
use tame_oidc::auth_scheme::{AuthenticationScheme, ClientAuthentication, PkceCredentials};
use tame_oidc::provider::Claims;
use tame_oidc::{
    oidc::Token,
    provider::{self, Provider, JWKS},
};

fn http_status_ok() -> String {
    "HTTP/1.1 200 OK\r\n\r\n".to_string()
}

fn handle_connection(mut stream: TcpStream) -> Option<String> {
    let mut reader = BufReader::new(&stream);
    let mut request = String::new();
    reader.read_line(&mut request).unwrap();

    let query_params = request.split_whitespace().nth(1).unwrap();
    let url = Url::parse(&format!("http://127.0.0.1:8000{query_params}")).unwrap();

    stream.write_all(http_status_ok().as_bytes()).unwrap();
    stream.flush().unwrap();

    // Extract the `code` query param and value
    url.query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, code)| code.to_string())
}

/// Spins up a listener on port, waits for any request from
/// the authentication provider and tries to return an `auth_code`
async fn listener(host: &str, port: u16) -> String {
    let urn = format!("{host}:{port}");
    let listener = TcpListener::bind(&urn).unwrap();
    println!("Listening on {}", urn);

    let mut auth_code = String::new();
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        if let Some(code) = handle_connection(stream) {
            auth_code = code;
            break;
        };
    }

    auth_code.trim().to_string()
}

/// Return reqwest response
async fn http_send<Body: Into<reqwest::Body>>(
    http_client: &reqwest::Client,
    request: Request<Body>,
) -> http::Response<Bytes> {
    // Make the request
    let mut response = http_client
        .execute(request.try_into().unwrap())
        .await
        .unwrap();
    // Convert to http::Response
    let mut builder = http::Response::builder()
        .status(response.status())
        .version(response.version());
    std::mem::swap(builder.headers_mut().unwrap(), response.headers_mut());
    builder.body(response.bytes().await.unwrap()).unwrap()
}

#[tokio::main]
async fn main() {
    let http_client = reqwest::Client::new();
    let mut rng = ThreadRng::default();
    let mut state = [0u8; 64];
    rng.fill_bytes(&mut state);
    let state_str = data_encoding::BASE64URL.encode(&state);

    let mut verifier = [0u8; 32];
    rng.fill_bytes(&mut verifier);
    let verifier_str = data_encoding::BASE64URL_NOPAD.encode(&verifier);
    let challenge_digest = ring::digest::digest(&ring::digest::SHA256, verifier_str.as_bytes());
    let challenge = data_encoding::BASE64URL_NOPAD.encode(challenge_digest.as_ref());
    let challenge_method = "S256".to_string();

    let issuer_domain = std::env::var("ISSUER_DOMAIN").unwrap();
    // Secret is optional in the PKCE flow
    let client_secret = std::env::var("CLIENT_SECRET").ok();
    let client_id = std::env::var("CLIENT_ID").unwrap();
    let host = "127.0.0.1";
    let port = 8000u16;
    // It's very important that this exactly matches where it's provided in other places, protocol and trailing slash all
    let redirect_uri = format!("http://{host}:{port}/");

    // Fetch and instantiate a provider using a `well-known` uri from an issuer
    let request = provider::well_known(&issuer_domain).unwrap();
    let response = http_send(&http_client, request).await;
    let provider = Provider::from_response(response).unwrap();
    let auth_endpoint = provider.authorization_endpoint.to_string();
    // 1. Authenticate through web browser
    // user goes to embark auth url in browser
    // auth service returns auth_code to listener at `redirect_uri`
    // Add idp-specific extra query-parameters to the below `authorize_url`
    let authorize_url = format!(
        "{auth_endpoint}?\
code_challenge={challenge}&\
code_challenge_method=S256&\
response_type=code&\
client_id={client_id}&\
redirect_uri={redirect_uri}&\
state={state_str}&\
scope=openid+offline",
    );
    println!("Authorize at {authorize_url}");

    let auth_code = listener(host, port).await;
    println!("Listener closed down");
    println!("Final code {}", auth_code);

    // 3. User now has 2 minutes to swap the auth code for an Embark Access token.
    // Make a `POST` request to the auth service /oauth2/token
    let scheme = AuthenticationScheme::Pkce(PkceCredentials::new(
        challenge.clone(),
        challenge_method.clone(),
        verifier_str.clone(),
        client_secret.clone(),
    ));
    let client_authentication = ClientAuthentication::new(client_id, scheme, None, None);
    let exchange_request = provider
        .exchange_token_request(&redirect_uri, &client_authentication, &auth_code)
        .unwrap();

    let response = http_send(&http_client, exchange_request).await;

    // construct the response
    let access_token = Token::from_response(response).unwrap();

    // 4. Fetch the required JWKs
    let request = provider.jwks_request().unwrap();
    let response = http_send(&http_client, request).await;
    let jwks = JWKS::from_response(response).unwrap();

    let token_data = provider::verify_token::<Claims>(&access_token.access_token, &jwks.keys);
    dbg!(&token_data);
    dbg!(&access_token);
    let refresh_token = access_token.refresh_token.unwrap();

    // 5. Refresh token
    let request = provider
        .refresh_token_request(&client_authentication, &refresh_token)
        .unwrap();
    let response = http_send(&http_client, request).await;
    let new_refresh_token = Token::from_response(response).unwrap();
    dbg!(&new_refresh_token);
}
