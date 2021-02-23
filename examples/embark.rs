use std::io::BufReader;
use std::net::{TcpListener, TcpStream};
use std::str;
use std::{convert::TryInto, io::prelude::*};

use bytes::Bytes;
use http::Request;
use reqwest::Url;

use tame_oidc::provider::JWKS;
use tame_oidc::{oidc, provider};

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
) -> reqwest::Response {
    http_client
        .execute(request.try_into().unwrap())
        .await
        .unwrap()
}

async fn convert_http_response(mut response: reqwest::Response) -> http::Response<Bytes> {
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
    let p_req = provider::well_known(&issuer_domain).unwrap();
    let response = http_send(&http_client, p_req).await;
    let provider_str = response.text().await.unwrap();
    let embark_provider = provider::from_str(&provider_str);
    dbg!(&embark_provider);

    // 1. Authenticate through web browser
    // user goes to embark auth url in browser
    // auth service returns auth_code to listener at `redirect_uri`
    let auth_code = listener(redirect_uri).await;
    println!("Listener closed down");
    println!("Final code {}", auth_code);

    // 3. User now has 2 minutes to swap the auth code for an Embark Access token.
    // Make a `POST` request to the auth service /oauth2/token
    let exchange_request = oidc::exchange_token_request(
        &embark_provider.token_endpoint,
        "http://127.0.0.1:8000",
        &client_id,
        &client_secret,
        &auth_code,
    );
    dbg!(&exchange_request);

    let response = http_send(&http_client, exchange_request).await;
    dbg!(&response);
    println!(" ========= ");

    // construct the response
    let token_response = convert_http_response(response).await;
    let access_token = oidc::parse_token_response(token_response).unwrap();

    // Fetch the required JWKs
    let jwks_req = provider::jwks(&embark_provider.jwks_uri);
    let jwks_res = http_send(&http_client, jwks_req).await;
    let jwks_str = jwks_res.text().await.unwrap();
    let jwks_json = serde_json::from_str::<JWKS>(&jwks_str).unwrap();
    dbg!(&jwks_json);

    let token_data = provider::token_data(&access_token.access_token, &jwks_json.keys);
    dbg!(&token_data);
}
