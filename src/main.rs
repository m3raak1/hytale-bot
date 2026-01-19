use quinn::{Endpoint};
use uuid::Uuid;

mod token;
mod net;
mod protocol;

const PORT: u16 = 5520;
const SERVER_ADDRESS: &str = "72.60.149.222";
const USERNAME: &str = "M3raak1";
const UUID: &str = "01c303eb-11e3-4717-93aa-06a6f5aa44f0";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  tracing_subscriber::fmt::init();

  // Server data
  let server_address = format!("{}:{}", SERVER_ADDRESS, PORT);

  let username = USERNAME;
  let uuid: Uuid = Uuid::parse_str(UUID)?;

  println!("Iniciando autenticação...");

  // 1. Obter Token de Acesso (Login Web)
  let token_data = token::get_access_token().await?;
  let access_token = &token_data.access_token;

  // 2. Criar Sessão de Jogo
  let session_response = token::create_game_session(access_token, uuid).await?;

  // 3. Conectar ao Servidor de Jogo
  let (config, x509_fingerprint) = net::configure_client();

  let mut game_client = Endpoint::client("[::]:0".parse()?)?;
  game_client.set_default_client_config(config);

  println!("Conectando ao servidor de jogo...");
  let connection = game_client.connect(server_address.parse()?, "hytale_server")?.await
    .map_err(|e| format!("Falha ao conectar ao servidor de jogo: {}", e))?;

  // Aqui você pode iniciar a comunicação com o servidor de jogo usando `connection`
  match connection.open_bi().await {
        Ok((mut send, mut recv)) => {

        let packet = protocol::packets::build_connect_packet_with_token(username, uuid, &session_response.identityToken);
        send.write_all(&packet).await?;

        // Passamos o sessionToken, identityToken e fingerprint
        if let Err(e) = protocol::handler::handle_auth_flow_network(
            &mut send,
            &mut recv,
            &session_response.identityToken,
            &session_response.sessionToken,
            &x509_fingerprint
        ).await {
            println!("Erro durante autenticação: {}", e);
        } else {
            println!("Autenticação concluída com sucesso!");


        }

      }
      Err(e) => {
          println!("Falha ao abrir canal bidirecional: {}", e);
      }
  }

  Ok(())
}
