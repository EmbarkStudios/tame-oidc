use bytes::Bytes;
use http::Request;
use reqwest::Url;
use std::{
    convert::TryInto,
    io::{prelude::*, BufReader},
    net::{TcpListener, TcpStream},
    str,
};
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
    let url = Url::parse(&("http://127.0.0.1:8000".to_string() + query_params)).unwrap();

    stream.write_all(http_status_ok().as_bytes()).unwrap();
    stream.flush().unwrap();

    // Extract the `code` query param and value
    url.query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, code)| code.to_string())
}

/// Spins up a listener on port, waits for any request from
/// the authentication provider and tries to return an `auth_code`
async fn listener(redirect_uri: &str) -> String {
    let listener = TcpListener::bind(redirect_uri).unwrap();
    println!("Listening on {}", redirect_uri);

    let mut auth_code = String::new();
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        if let Some(code) = handle_connection(stream) {
            auth_code = code;
            break;
        };
    }

    auth_code
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

    let issuer_domain = std::env::var("ISSUER_DOMAIN").unwrap();
    let client_secret = std::env::var("CLIENT_SECRET").unwrap();
    let client_id = std::env::var("CLIENT_ID").unwrap();
    let redirect_uri = "127.0.0.1:8000";

    // Fetch and instantiate a provider using a `well-known` uri from an issuer
    let request = provider::well_known(&issuer_domain).unwrap();
    let response = http_send(&http_client, request).await;
    let provider = Provider::from_response(response).unwrap();
    dbg!(&provider);

    // 1. Authenticate through web browser
    // user goes to embark auth url in browser
    // auth service returns auth_code to listener at `redirect_uri`
    let auth_code = listener(redirect_uri).await;
    println!("Listener closed down");
    println!("Final code {}", auth_code);

    // 3. User now has 2 minutes to swap the auth code for an Embark Access token.
    // Make a `POST` request to the auth service /oauth2/token
    let exchange_request = provider
        .exchange_token_request(redirect_uri, &client_id, &client_secret, &auth_code)
        .unwrap();
    dbg!(&exchange_request);

    let response = http_send(&http_client, exchange_request).await;
    dbg!(&response);
    println!(" ========= ");

    // construct the response
    let access_token = Token::from_response(response).unwrap();

    // 4. Fetch the required JWKs
    let request = provider.jwks_request().unwrap();
    let response = http_send(&http_client, request).await;
    let jwks = JWKS::from_response(response).unwrap();
    dbg!(&jwks);

    let token_data = provider::token_data(&access_token.access_token, &jwks.keys);
    dbg!(&token_data);
    dbg!(&access_token);
    let refresh_token = access_token.refresh_token.unwrap();

    // 5. Refresh token
    let request = provider
        .refresh_token_request(&client_id, &client_secret, &refresh_token)
        .unwrap();
    let response = http_send(&http_client, request).await;
    let new_refresh_token = Token::from_response(response).unwrap();
    dbg!(&new_refresh_token);
}
