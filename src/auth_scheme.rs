#[derive(Debug)]
pub struct ClientAuthentication {
    pub client_id: String,
    pub scheme: AuthenticationScheme,
    pub nonce: Option<String>,
    pub state: Option<String>,
}

impl ClientAuthentication {
    pub fn new(
        client_id: String,
        scheme: AuthenticationScheme,
        nonce: Option<String>,
        state: Option<String>,
    ) -> Self {
        ClientAuthentication {
            client_id,
            scheme,
            nonce,
            state,
        }
    }
}
#[derive(Debug)]
pub enum AuthenticationScheme {
    Basic(ClientCredentials),
    Post(ClientCredentials),
    Pkce(PkceCredentials),
}

#[derive(Debug)]
pub struct ClientCredentials {
    pub client_secret: String,
}

impl ClientCredentials {
    pub fn new(client_secret: String) -> Self {
        ClientCredentials { client_secret }
    }
}

#[derive(Debug)]
pub struct PkceCredentials {
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub code_verifier: String,
    pub client_secret: Option<String>,
}

impl PkceCredentials {
    pub fn new(
        code_challenge: String,
        code_challenge_method: String,
        code_verifier: String,
        client_secret: Option<String>,
    ) -> Self {
        PkceCredentials {
            code_challenge,
            code_challenge_method,
            code_verifier,
            client_secret,
        }
    }
}
