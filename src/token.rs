use base64::{engine::general_purpose, Engine as _};
use rand::{distributions::Alphanumeric, Rng};
use reqwest::Client;
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;
use warp::Filter;
use uuid::Uuid;

// Configurações Constantes do Hytale
const CLIENT_ID: &str = "hytale-launcher";
const AUTH_URL: &str = "https://oauth.accounts.hytale.com/oauth2/auth";
const TOKEN_URL: &str = "https://oauth.accounts.hytale.com/oauth2/token";
const REDIRECT_URI: &str = "https://accounts.hytale.com/consent/client";
const LOCAL_PORT: u16 = 43803;

#[derive(Deserialize, Debug, Clone)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: u64,
    pub scope: String,
    pub token_type: String,
}

#[derive(Serialize)]
struct StateData {
    state: String,
    port: String,
}

#[derive(Deserialize)]
struct CodeQuery {
    code: String,
}

pub async fn get_access_token() -> Result<TokenResponse, Box<dyn std::error::Error>> {
    // 1. Gerar PKCE (Verifier e Challenge)
    let code_verifier = generate_verifier();
    let code_challenge = generate_challenge(&code_verifier);

    // Gerar um estado aleatório para segurança
    let random_state: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    // 2. Preparar o Servidor Local para receber o Code
    let (code_tx, mut code_rx) = oneshot::channel::<String>();
    let code_tx = Arc::new(Mutex::new(Some(code_tx)));

    // Removido graceful shutdown via Warp para compatibilidade com versões sem esse método.

    // Rota: /authorization-callback?code=...
    let callback_route = warp::path("authorization-callback")
        .and(warp::get())
        .and(warp::query::<CodeQuery>())
        .map(move |params: CodeQuery| {
            let code = params.code;
            if let Some(tx) = code_tx.lock().unwrap().take() {
                let _ = tx.send(code.clone());
            }
            warp::reply::html("Autenticação concluída! Você pode fechar esta aba.")
        });

    // Iniciar o servidor em uma thread separada (não bloqueante)
    let server_handle = tokio::spawn(warp::serve(callback_route).run(([127, 0, 0, 1], LOCAL_PORT)));

    // 3. Construir a URL de Login
    // IMPORTANTE: O parâmetro 'state' deve conter a porta em JSON Base64
    let state_json = serde_json::to_string(&StateData {
        state: random_state,
        port: LOCAL_PORT.to_string(),
    })?;
    let state_encoded = general_purpose::URL_SAFE_NO_PAD.encode(state_json);

    let client = Client::new();

    // Construção da URL
    let url = url::Url::parse_with_params(AUTH_URL, &[
        ("client_id", CLIENT_ID),
        ("response_type", "code"),
        ("scope", "openid offline auth:launcher"),
        ("redirect_uri", REDIRECT_URI), // Note: enviamos a URL da Riot, não localhost
        ("code_challenge_method", "S256"),
        ("code_challenge", &code_challenge),
        ("state", &state_encoded),
    ])?;

    println!("\n🌐 Abrindo navegador para login...");
    println!("Link (caso nao abra): {}", url);

    if webbrowser::open(url.as_str()).is_err() {
        println!("⚠️  Falha ao abrir navegador automaticamente. Copie o link acima.");
    }

    let auth_code = match code_rx.await {
        Ok(code) => code,
        Err(_) => {
            return Err("Falha ao receber o código de autorização.".into());
        }
    };

    // Encerrar o servidor web explicitamente após receber o código
    server_handle.abort();

    let params = [
        ("client_id", CLIENT_ID),
        ("grant_type", "authorization_code"),
        ("redirect_uri", REDIRECT_URI), // Deve ser IDENTICO ao do passo 3
        ("code", &auth_code),
        ("code_verifier", &code_verifier),
    ];

    let response = client
        .post(TOKEN_URL)
        .form(&params)
        .send()
        .await?;

    if response.status().is_success() {
        let token_data: TokenResponse = response.json().await?;
        Ok(token_data)
    } else {
        let status = response.status();
        let body = response.text().await?;
        Err(format!("Erro na troca do token: {} - {}", status, body).into())
    }
}

// --- Funções Auxiliares PKCE ---

fn generate_verifier() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64) // Entre 43 e 128
        .map(char::from)
        .collect()
}

fn generate_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();

    general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

// --- Função para criar sessão de jogo ---

#[derive(Deserialize, Debug)]
pub struct GameSessionResponse {
    pub identityToken: String,
    pub sessionToken: String,
}

pub async fn create_game_session(access_token: &str, player_uuid: Uuid) -> Result<GameSessionResponse, Box<dyn std::error::Error>> {
    let client = Client::new();
    let url = "https://sessions.hytale.com/game-session/new";

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("Authorization", format!("Bearer {}", access_token).parse()?);
    headers.insert("Content-Type", "application/json".parse()?);
    let body = serde_json::json!({
        "uuid": player_uuid.to_string()
    });
    let response = client
        .post(url)
        .headers(headers)
        .json(&body)
        .send()
        .await?;

    if response.status().is_success() {
        let resp_text = response.text().await?;
        let game_session_response: GameSessionResponse = serde_json::from_str(&resp_text)?;
        Ok(game_session_response)
    } else {
        let err_text = response.text().await?;
        Err(format!("Erro ao criar sessão de jogo: {}", err_text).into())
    }
}

pub async fn exchange_grant_for_access_token(
    authorization_grant: &str,
    session_token: &str,
    x509_fingerprint: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::new();
    let url = "https://sessions.hytale.com/server-join/auth-token";

    let body = serde_json::json!({
        "authorizationGrant": authorization_grant,
        "x509Fingerprint": x509_fingerprint.trim_end_matches("=")
    });

    let response = client
        .post(url)
        .header("Authorization", format!("Bearer {}", session_token))
        .header("Content-Type", "application/json")
        .header("User-Agent", "Hytale/1.0")
        .json(&body)
        .send()
        .await?;

    if response.status().is_success() {
        let resp_text = response.text().await?;

        // Parse JSON para extrair accessToken
        let json: serde_json::Value = serde_json::from_str(&resp_text)?;

        if let Some(access_token) = json.get("accessToken").and_then(|v| v.as_str()) {
            println!("✅ AccessToken obtido da API!");
            Ok(access_token.to_string())
        } else {
            Err(format!("Resposta sem accessToken: {}", resp_text).into())
        }
    } else {
        let status = response.status();
        let err_text = response.text().await?;
        Err(format!("Erro ao trocar grant por token: {} - {}", status, err_text).into())
    }
}

/// Gera um authorization grant para o servidor
/// O cliente chama isso para gerar um grant que o servidor vai trocar por token
pub async fn request_server_auth_grant(
    identity_token: &str,
    server_audience: &str,  // UUID do servidor (extraído do serverIdentityToken)
    session_token: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::new();
    let url = "https://sessions.hytale.com/server-join/auth-grant";

    let body = serde_json::json!({
        "identityToken": identity_token,
        "aud": server_audience
    });

    println!("🔄 Gerando grant para servidor (aud: {})...", server_audience);
    println!("📤 Request body: {}", body);

    let response = client
        .post(url)
        .header("Authorization", format!("Bearer {}", session_token))
        .header("Content-Type", "application/json")
        .header("User-Agent", "Hytale/1.0")
        .json(&body)
        .send()
        .await?;

    println!("📥 Response status: {}", response.status());

    if response.status().is_success() {
        let resp_text = response.text().await?;
        let json: serde_json::Value = serde_json::from_str(&resp_text)?;

        if let Some(grant) = json.get("authorizationGrant").and_then(|v| v.as_str()) {
            println!("✅ Grant para servidor obtido!");
            Ok(grant.to_string())
        } else {
            Err(format!("Resposta sem authorizationGrant: {}", resp_text).into())
        }
    } else {
        let status = response.status();
        let err_text = response.text().await?;
        Err(format!("Erro ao gerar grant para servidor: {} - {}", status, err_text).into())
    }
}
