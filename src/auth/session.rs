//! Game session management

use reqwest::Client;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct GameSessionResponse {
    pub identityToken: String,
    pub sessionToken: String,
}

/// Cria uma nova sessão de jogo com o servidor Hytale
pub async fn create_game_session(
    access_token: &str,
    player_uuid: Uuid,
) -> Result<GameSessionResponse, Box<dyn std::error::Error>> {
    let client = Client::new();
    let url = "https://sessions.hytale.com/game-session/new";

    let body = serde_json::json!({
        "uuid": player_uuid.to_string()
    });

    let response = client
        .post(url)
        .header("Authorization", format!("Bearer {}", access_token))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await?;

    if response.status().is_success() {
        let resp_text = response.text().await?;
        let session: GameSessionResponse = serde_json::from_str(&resp_text)?;
        Ok(session)
    } else {
        let err_text = response.text().await?;
        Err(format!("Erro ao criar sessão de jogo: {}", err_text).into())
    }
}
