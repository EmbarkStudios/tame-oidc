use bytes::Bytes;
use http::Request;
use std::{
    convert::TryInto,
    io::{prelude::*, stdin, stdout},
};
use tame_oidc::auth_scheme::{AuthenticationScheme, ClientAuthentication, ClientCredentials};
use tame_oidc::strict::{ClientInfoStage, Finalized};

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

async fn get_auth_code_input(state: Option<String>) -> (String, Option<String>) {
    let mut s = String::new();
    println!("Please enter authorization token:");
    let _ = stdout().flush();
    stdin()
        .read_line(&mut s)
        .expect("Could not read token from stdin");
    s.pop();
    (s, state)
}

/// Example user info struct to deserialize user_info into
#[derive(serde::Deserialize, Debug)]
#[allow(dead_code)]
struct UserInfo {
    sub: String,
    email: String,
    email_verified: bool,
    phone_number: String,
    phone_number_verified: bool,
}

#[tokio::main]
async fn main() {
    let http_client = reqwest::Client::new();

    let issuer_domain = "https://www.certification.openid.net/...".to_owned(); // TODO: Oidc generated
    let client_id = "my_client".to_owned();
    let client_secret = "abc123".to_owned();
    let redirect_uri = ""; // TODO: Add correct endpoint
    let state = "dummy".to_owned();
    let client_info_stage = ClientInfoStage::new(
        issuer_domain,
        ClientAuthentication::new(
            client_id,
            AuthenticationScheme::Basic(ClientCredentials::new(client_secret)),
            None,
            Some(state.clone()),
        ),
        redirect_uri.to_owned(),
        Some(vec![
            "openid".to_owned(),
            "profile".to_owned(),
            "email".to_owned(),
            "phone".to_owned(),
            "address".to_owned(),
        ]),
    );
    let send = |req: Request<Vec<u8>>| http_send(&http_client, req);
    let code = get_auth_code_input(Some(state));
    let finalized: Finalized<UserInfo> = client_info_stage.run_to_end(send, code).await.unwrap();
    println!("{:?}", finalized);
}
