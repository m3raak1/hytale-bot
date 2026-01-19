//! OAuth 2.0 + PKCE authentication flow for Hytale

use base64::{engine::general_purpose, Engine as _};
use rand::{distributions::Alphanumeric, Rng};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;
use warp::Filter;

// ============================================================================
// Constantes OAuth
// ============================================================================

const CLIENT_ID: &str = "hytale-launcher";
const AUTH_URL: &str = "https://oauth.accounts.hytale.com/oauth2/auth";
const TOKEN_URL: &str = "https://oauth.accounts.hytale.com/oauth2/token";
const REDIRECT_URI: &str = "https://accounts.hytale.com/consent/client";
const LOCAL_PORT: u16 = 43803;

// ============================================================================
// Tipos
// ============================================================================

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

// ============================================================================
// PKCE Helpers
// ============================================================================

fn generate_verifier() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect()
}

fn generate_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

// ============================================================================
// OAuth Flow
// ============================================================================

/// Inicia o fluxo OAuth e retorna os tokens de acesso
pub async fn get_access_token() -> Result<TokenResponse, Box<dyn std::error::Error>> {
    let code_verifier = generate_verifier();
    let code_challenge = generate_challenge(&code_verifier);

    let random_state: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    // Servidor local para receber callback
    let (code_tx, code_rx) = oneshot::channel::<String>();
    let code_tx = Arc::new(Mutex::new(Some(code_tx)));

    let callback_route = warp::path("authorization-callback")
        .and(warp::get())
        .and(warp::query::<CodeQuery>())
        .map(move |params: CodeQuery| {
            if let Some(tx) = code_tx.lock().unwrap().take() {
                let _ = tx.send(params.code.clone());
            }
            warp::reply::html("Autenticação concluída! Você pode fechar esta aba.")
        });

    let server_handle = tokio::spawn(warp::serve(callback_route).run(([127, 0, 0, 1], LOCAL_PORT)));

    // Construir URL de login
    let state_json = serde_json::to_string(&StateData {
        state: random_state,
        port: LOCAL_PORT.to_string(),
    })?;
    let state_encoded = general_purpose::URL_SAFE_NO_PAD.encode(state_json);

    let url = url::Url::parse_with_params(AUTH_URL, &[
        ("client_id", CLIENT_ID),
        ("response_type", "code"),
        ("scope", "openid offline auth:launcher"),
        ("redirect_uri", REDIRECT_URI),
        ("code_challenge_method", "S256"),
        ("code_challenge", &code_challenge),
        ("state", &state_encoded),
    ])?;

    println!("\n🌐 Abrindo navegador para login...");
    println!("Link (caso não abra): {}", url);

    if webbrowser::open(url.as_str()).is_err() {
        println!("⚠️  Falha ao abrir navegador automaticamente. Copie o link acima.");
    }

    let auth_code = code_rx.await
        .map_err(|_| "Falha ao receber o código de autorização.")?;

    server_handle.abort();

    // Trocar code por token
    let client = Client::new();
    let params = [
        ("client_id", CLIENT_ID),
        ("grant_type", "authorization_code"),
        ("redirect_uri", REDIRECT_URI),
        ("code", &auth_code),
        ("code_verifier", &code_verifier),
    ];

    let response = client.post(TOKEN_URL).form(&params).send().await?;

    if response.status().is_success() {
        Ok(response.json().await?)
    } else {
        let status = response.status();
        let body = response.text().await?;
        Err(format!("Erro na troca do token: {} - {}", status, body).into())
    }
}
