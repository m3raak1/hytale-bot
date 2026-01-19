use quinn::{Endpoint};
use uuid::Uuid;

mod token;
mod net;
mod protocol;

const PORT: u16 = 5520;
const SERVER_ADDRESS: &str = "72.60.149.222";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  tracing_subscriber::fmt::init();

  // Server data
  let server_address = format!("{}:{}", SERVER_ADDRESS, PORT);

  print!("Package Data:");
  let username = "Null_v1";
  let uuid: Uuid = Uuid::parse_str("350beb9a-818a-4504-9386-39b37d809fa7")?;

  println!("Iniciando autenticação...");

  // 1. Obter Token de Acesso (Login Web)
  let token_data = token::get_access_token().await?;
  let access_token = &token_data.access_token;

  print!("Token de Acesso obtido.");

  // 2. Criar Sessão de Jogo
  let session_response = token::create_game_session(access_token, uuid).await?;
  println!("Sessão criada.");

  // 3. Conectar ao Servidor de Jogo
  let (config, x509_fingerprint) = net::configure_client();

  let mut game_client = Endpoint::client("[::]:0".parse()?)?;
  game_client.set_default_client_config(config);

  println!("Conectando ao servidor de jogo...");
  let connection = game_client.connect(server_address.parse()?, "hytale_server")?.await
    .map_err(|e| format!("Falha ao conectar ao servidor de jogo: {}", e))?;

  println!("Conectado ao servidor de jogo.");

  // Aqui você pode iniciar a comunicação com o servidor de jogo usando `connection`
  match connection.open_bi().await {
      Ok((mut send, mut recv)) => {
          println!("Canal bidirecional aberto com sucesso.");

          let packet = protocol::packets::build_connect_packet_with_token(username, uuid, &session_response.identityToken);
          send.write_all(&packet).await?;

          println!("Pacote de conexão enviado ao servidor.");

          // Passamos o sessionToken (gerado pela API de sessão) em vez do identityToken para a etapa de AuthToken
          if let Err(e) = protocol::handler::handle_auth_flow_network(&mut send, &mut recv, &session_response.identityToken, &session_response.sessionToken, &x509_fingerprint).await {
              println!("Erro durante autenticação: {}", e);
          } else {
              println!("Autenticação realizada com sucesso!");
          }

      }
      Err(e) => {
          println!("Falha ao abrir canal bidirecional: {}", e);
      }
  }

  Ok(())
}

