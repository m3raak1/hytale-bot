//! Auth flow handler

use std::error::Error;
use quinn::{SendStream, RecvStream};
use super::constants::*;
use super::codec::*;
use super::packets::*;
use crate::auth::{exchange_grant_for_access_token, request_server_auth_grant};
use crate::utils::extract_jwt_subject;

type BoxError = Box<dyn Error + Send + Sync>;

// ============================================================================
// Estruturas de Pacotes
// ============================================================================

#[derive(Debug)]
pub struct AuthGrantPacket {
    pub authorization_grant: Option<String>,
    pub server_identity_token: Option<String>,
}

#[derive(Debug)]
pub struct ServerAuthTokenPacket {
    pub server_access_token: Option<String>,
    pub password_challenge: Option<Vec<u8>>,
}

// ============================================================================
// Parsing de Pacotes
// ============================================================================

pub fn parse_auth_grant(data: &[u8]) -> Option<AuthGrantPacket> {
    if data.len() < 9 { return None; }

    const VAR_BLOCK_START: usize = 9;
    let offset_grant = read_i32_le(data, 1);
    let offset_sit = read_i32_le(data, 5);

    Some(AuthGrantPacket {
        authorization_grant: read_varstring_at(data, VAR_BLOCK_START, offset_grant),
        server_identity_token: read_varstring_at(data, VAR_BLOCK_START, offset_sit),
    })
}

pub fn parse_server_auth_token(data: &[u8]) -> Option<ServerAuthTokenPacket> {
    if data.len() < 9 { return None; }

    const VAR_BLOCK_START: usize = 9;
    let offset_sat = read_i32_le(data, 1);
    let offset_pwd = read_i32_le(data, 5);

    Some(ServerAuthTokenPacket {
        server_access_token: read_varstring_at(data, VAR_BLOCK_START, offset_sat),
        password_challenge: read_varbytes_at(data, VAR_BLOCK_START, offset_pwd),
    })
}

// ============================================================================
// Handlers de Pacotes Individuais
// ============================================================================

async fn handle_auth_grant(
    send: &mut SendStream,
    payload: &[u8],
    identity_token: &str,
    session_token: &str,
    x509_fingerprint: &str,
) -> Result<(), BoxError> {
    let auth_grant = parse_auth_grant(payload)
        .ok_or("Falha ao parsear AuthGrant")?;

    let grant = auth_grant.authorization_grant
        .ok_or("AuthGrant sem authorization_grant")?;

    // Trocar grant por access token
    let access_token = exchange_grant_for_access_token(&grant, session_token, x509_fingerprint).await?;

    // Gerar grant para o servidor (se tiver serverIdentityToken)
    let server_grant = generate_server_grant(&auth_grant.server_identity_token, identity_token, session_token).await;

    let auth_token = build_auth_token(Some(&access_token), server_grant.as_deref());
    send.write_all(&auth_token).await?;

    Ok(())
}

async fn generate_server_grant(
    server_identity_token: &Option<String>,
    identity_token: &str,
    session_token: &str,
) -> Option<String> {
    let server_identity = server_identity_token.as_ref()?;

    let server_uuid = extract_jwt_subject(server_identity).or_else(|| {
        println!("⚠️ Não foi possível extrair UUID do serverIdentityToken");
        None
    })?;

    match request_server_auth_grant(identity_token, &server_uuid, session_token).await {
        Ok(grant) => Some(grant),
        Err(e) => {
            println!("⚠️ Falha ao gerar grant para servidor: {}", e);
            None
        }
    }
}

fn handle_server_auth_token(payload: &[u8]) -> Result<bool, BoxError> {
    println!("🔐 Recebido ServerAuthToken - autenticação avançando!");

    let server_auth = parse_server_auth_token(payload)
        .ok_or("Falha ao parsear ServerAuthToken")?;

    if server_auth.password_challenge.is_some() {
        println!("⚠️ Servidor pediu senha (PasswordChallenge), não implementado.");
        return Ok(false); // Continuar loop
    }

    Ok(true) // Auth completa
}

async fn handle_ping(send: &mut SendStream, payload: &[u8]) -> Result<(), BoxError> {
    println!("🏓 Ping recebido durante handshake, respondendo Pong...");

    if payload.len() < 17 {
        return Err("Payload de Ping muito curto".into());
    }

    let ping_id = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
    let seconds = i64::from_le_bytes([
        payload[5], payload[6], payload[7], payload[8],
        payload[9], payload[10], payload[11], payload[12]
    ]);
    let nanos = i32::from_le_bytes([payload[13], payload[14], payload[15], payload[16]]);

    let pong = build_pong_packet(ping_id, seconds, nanos);
    send.write_all(&pong).await?;

    Ok(())
}

// ============================================================================
// Loop Principal de Auth
// ============================================================================

pub async fn handle_auth_flow_network(
    send: &mut SendStream,
    recv: &mut RecvStream,
    identity_token: &str,
    session_token: &str,
    x509_fingerprint: &str,
) -> Result<(), BoxError> {
    loop {
        let (packet_id, payload) = read_packet(recv).await?;

        match packet_id {
            PACKET_DISCONNECT => {
                println!("⛔ Servidor desconectou!");
                return Err("Desconectado pelo servidor".into());
            }

            PACKET_AUTH_GRANT => {
                handle_auth_grant(send, &payload, identity_token, session_token, x509_fingerprint).await?;
            }

            PACKET_SERVER_AUTH_TOKEN => {
                if handle_server_auth_token(&payload)? {
                    return Ok(());
                }
            }

            PACKET_CONNECT_ACCEPT => {
                println!("🎉 ConnectAccept - Conexão totalmente aceita!");
                return Ok(());
            }

            PACKET_PING => {
                handle_ping(send, &payload).await?;
            }

            _ => {
                println!("❓ Pacote desconhecido durante Auth: {} (ID: {})", get_packet_name(packet_id), packet_id);
            }
        }
    }
}
