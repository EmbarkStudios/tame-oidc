use std::io::prelude::*;
use std::io::BufReader;
use std::net::{TcpListener, TcpStream};
use std::str;

use http::response::Builder;
use http::Request;
use reqwest::Url;

use tame_oidc::provider::JWKS;
use tame_oidc::{issuers, oidc, provider};

fn http_status_ok() -> String {
    format!("HTTP/1.1 200 OK\r\n\r\n")
}

fn handle_connection(mut stream: TcpStream) -> Option<String> {
    let mut reader = BufReader::new(&stream);
    let mut request = String::new();
    reader.read_line(&mut request).unwrap();

    let query_params = request.split_whitespace().nth(1).unwrap();
    let url = Url::parse(&("http://127.0.0.1:8000".to_string() + query_params)).unwrap();

    // Extract the `code` query param and value
    let code_pair = url.query_pairs().find(|pair| {
        let &(ref key, _) = pair;
        key == "code"
    });

    stream.write(http_status_ok().as_bytes()).unwrap();
    stream.flush().unwrap();

    return match code_pair {
        Some(cp) => {
            let (_, code) = cp;
            Some(code.to_string())
        }
        _ => None,
    };
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
async fn http_builder(
    http_client: &reqwest::Client,
    request: Request<Vec<u8>>,
) -> reqwest::Response {
    let (parts, body) = request.into_parts();
    let uri = parts.uri.to_string();

    let builder = match parts.method {
        http::Method::GET => http_client.get(&uri),
        http::Method::POST => http_client.post(&uri),
        http::Method::DELETE => http_client.delete(&uri),
        http::Method::PUT => http_client.put(&uri),
        method => unimplemented!("{} not implemented", method),
    };
    let request = builder.headers(parts.headers).body(body).build().unwrap();

    http_client.execute(request).await.unwrap()
}

///
/// Return reqwest response
async fn http_builder_get(
    http_client: &reqwest::Client,
    request: Request<()>,
) -> reqwest::Response {
    let (parts, _) = request.into_parts();
    let uri = parts.uri.to_string();

    let builder = match parts.method {
        http::Method::GET => http_client.get(&uri),
        http::Method::POST => http_client.post(&uri),
        http::Method::DELETE => http_client.delete(&uri),
        http::Method::PUT => http_client.put(&uri),
        method => unimplemented!("{} not implemented", method),
    };

    let request = builder.headers(parts.headers).build().unwrap();
    http_client.execute(request).await.unwrap()
}

fn resp_builder(response: &reqwest::Response) -> Builder {
    let mut builder = http::Response::builder()
        .status(response.status())
        .version(response.version());

    let headers = builder.headers_mut().unwrap();

    // Unfortunately http doesn't expose a way to just use
    // an existing HeaderMap, so we have to copy them :(
    headers.extend(
        response
            .headers()
            .into_iter()
            .map(|(k, v)| (k.clone(), v.clone())),
    );
    builder
}

#[tokio::main]
async fn main() {
    let http_client = reqwest::Client::new();

    let client_secret = "SUPER_SECRET".to_string();
    let client_id = "CLIENT_ID".to_string();
    let redirect_uri = "127.0.0.1:8000";

    // Fetch and instantiate a provider using a `well-known` uri from an issuer
    let p_req = provider::well_known(issuers::embark()).unwrap();
    let response = http_builder_get(&http_client, p_req).await;
    let provider_str = response.text().await.unwrap();
    let embark_provider = provider::from_str(&provider_str);
    dbg!(&embark_provider);

    // 1. Authenticate through web browser
    // user goes to embark auth url in browser
    // auth service returns auth_code to listener at `redirect_uri`
    let auth_code = listener(redirect_uri).await;
    println!("Listener closed down");
    println!("Final code {}", auth_code);

    // // 3. User now has 2 minutes to swap the auth code for an Embark Access token.
    // // Make a `POST` request to the auth service /oauth2/token
    let exchange_request = oidc::exchange_token_request(
        embark_provider.token_endpoint,
        "http://127.0.0.1:8000".to_string(),
        client_id,
        client_secret,
        auth_code,
    );
    dbg!(&exchange_request);

    let response = http_builder(&http_client, exchange_request).await;
    dbg!(&response);
    println!(" ========= ");

    // construct the response
    let builder = resp_builder(&response);
    let buffer = response.bytes().await.unwrap();
    let token_response = builder.body(buffer).unwrap();
    let access_token = oidc::parse_token_response(token_response).unwrap();

    // Fetch the required JWKs
    let jwks_req = provider::jwks(embark_provider.jwks_uri);
    let jwks_res = http_builder_get(&http_client, jwks_req).await;
    let jwks_str = jwks_res.text().await.unwrap();
    let jwks_json = serde_json::from_str::<JWKS>(&jwks_str).unwrap();
    dbg!(&jwks_json);

    let token_data =
        provider::token_data(access_token.access_token.to_string(), &jwks_json.keys[1]);
    dbg!(&token_data);
}
