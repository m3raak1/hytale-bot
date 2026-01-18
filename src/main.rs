use std::error::Error;
use tokio::sync::mpsc;
use uuid::Uuid;

mod token;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  tracing_subscriber::fmt::init();

  // Server data
  let port = 5520;
  let server_addreess = format!("72.60.149.222:{}", port);

  print!("Package Data:");
  let username = "Null_v1";
  let uuid = "6d9a74cf-ec5f-49ff-aab3-95e1a04a6b54";

  println!("Iniciando autenticação...");



  // 1. Obter Token de Acesso (Login Web)
  let token_data = token::get_access_token().await?;
  let access_token = &token_data.access_token;

  // 2. Criar Sessão de Jogo
  let session_response = token::create_game_session(access_token, uuid).await?;
  println!("Sessão criada: {}", session_response);

  Ok(())
}
