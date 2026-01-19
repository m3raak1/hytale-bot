//! Hytale API calls for server authentication

use reqwest::Client;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Troca um authorization grant por um access token
pub async fn exchange_grant_for_access_token(
    authorization_grant: &str,
    session_token: &str,
    x509_fingerprint: &str,
) -> Result<String, BoxError> {
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
pub async fn request_server_auth_grant(
    identity_token: &str,
    server_audience: &str,
    session_token: &str,
) -> Result<String, BoxError> {
    let client = Client::new();
    let url = "https://sessions.hytale.com/server-join/auth-grant";

    let body = serde_json::json!({
        "identityToken": identity_token,
        "aud": server_audience
    });

    println!("🔄 Gerando grant para servidor (aud: {})...", server_audience);

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
