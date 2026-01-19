use std::error::Error;
use quinn::{SendStream, RecvStream};
use serde::Deserialize;
use super::common::*;
use super::packets::*;
use crate::token::{exchange_grant_for_access_token, request_server_auth_grant};
use base64::{engine::general_purpose, Engine as _};

/// Estruturas para parsear respostas de pacotes
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

#[derive(Debug, serde::Serialize)]
struct AuthTokenRequest {
    #[serde(rename = "authorizationGrant")]
    authorization_grant: String,
    // Em teoria mTLS exige fingerprint, mas vamos simplificar se possível
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x509Fingerprint")]
    x509_fingerprint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AccessTokenResponse {
    #[serde(rename = "accessToken")]
    access_token: Option<String>,
    error: Option<String>,
}

// --- Funções de Parsing ---

/// Extrai o "sub" (UUID) de um JWT sem validar a assinatura
fn extract_jwt_subject(jwt: &str) -> Option<String> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() < 2 {
        return None;
    }

    // Decodifica o payload (segunda parte)
    let payload_b64 = parts[1];
    let payload_bytes = general_purpose::URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let payload_str = String::from_utf8(payload_bytes).ok()?;

    // Parse JSON e extrai "sub"
    let json: serde_json::Value = serde_json::from_str(&payload_str).ok()?;
    json.get("sub").and_then(|v| v.as_str()).map(|s| s.to_string())
}

pub fn parse_auth_grant(data: &[u8]) -> Option<AuthGrantPacket> {
    if data.is_empty() { return None; }
    let null_bits = data[0];

    // AuthGrant Offsets: (authorizationGrant, serverIdentityToken)
    // data[1..5] = offsetAuthorizationGrant
    // data[5..9] = offsetServerIdentityToken

    let mut grant: Option<String> = None;
    let mut sit: Option<String> = None;

    // authorizationGrant (Bit 0)
    // serverIdentityToken (Bit 1)

    // Simplificação: Leitura linear baseada em offsets é mais segura
    // Mas vamos assumir a ordem dos offsets para extração rápida
    if data.len() < 9 { return None; }

    let offset_grant = i32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    let offset_sit = i32::from_le_bytes([data[5], data[6], data[7], data[8]]);

    let var_block_start = 9;

    if offset_grant >= 0 {
        let pos = var_block_start + offset_grant as usize;
        if pos < data.len() {
             let (len, sz) = read_varint(&data[pos..]);
             if pos + sz + len as usize <= data.len() {
                 grant = String::from_utf8(data[pos + sz .. pos + sz + len as usize].to_vec()).ok();
             }
        }
    }

    if offset_sit >= 0 {
        let pos = var_block_start + offset_sit as usize;
        if pos < data.len() {
             let (len, sz) = read_varint(&data[pos..]);
             if pos + sz + len as usize <= data.len() {
                 sit = String::from_utf8(data[pos + sz .. pos + sz + len as usize].to_vec()).ok();
             }
        }
    }

    Some(AuthGrantPacket { authorization_grant: grant, server_identity_token: sit })
}

pub fn parse_server_auth_token(data: &[u8]) -> Option<ServerAuthTokenPacket> {
    if data.is_empty() { return None; }

    // data[1..5] = offsetServerAccessToken
    // data[5..9] = offsetPasswordChallenge

    let mut sat: Option<String> = None;
    let mut pwd: Option<Vec<u8>> = None;

    let offset_sat = i32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    let offset_pwd = i32::from_le_bytes([data[5], data[6], data[7], data[8]]);

    let var_block_start = 9;

    if offset_sat >= 0 {
        let pos = var_block_start + offset_sat as usize;
        if pos < data.len() {
             let (len, sz) = read_varint(&data[pos..]);
             if pos + sz + len as usize <= data.len() {
                 sat = String::from_utf8(data[pos + sz .. pos + sz + len as usize].to_vec()).ok();
             }
        }
    }

    if offset_pwd >= 0 {
        let pos = var_block_start + offset_pwd as usize;
        if pos < data.len() {
             let (len, sz) = read_varint(&data[pos..]);
             if pos + sz + len as usize <= data.len() {
                 pwd = Some(data[pos + sz .. pos + sz + len as usize].to_vec());
             }
        }
    }

    Some(ServerAuthTokenPacket { server_access_token: sat, password_challenge: pwd })
}


pub async fn handle_auth_flow_network(
    send: &mut SendStream,
    recv: &mut RecvStream,
    identity_token: &str,
    session_token: &str,  // sessionToken para autenticar na API
    x509_fingerprint: &str,  // fingerprint do certificado TLS
) -> Result<(), Box<dyn Error + Send + Sync>> {
    loop {
        let (packet_id, payload) = read_packet(recv).await?;

        match packet_id {
            PACKET_DISCONNECT => {
                println!("⛔ Servidor desconectou!");
                return Err("Desconectado pelo servidor".into());
            }

            PACKET_AUTH_GRANT => {
                if let Some(auth_grant) = parse_auth_grant(&payload) {
                    if let Some(grant) = &auth_grant.authorization_grant {

                        // Chamar a API para obter o accessToken real (com fingerprint)
                        match exchange_grant_for_access_token(grant, session_token, x509_fingerprint).await {
                            Ok(access_token) => {

                                // Agora gerar um grant PARA o servidor
                                let server_grant = if let Some(server_identity) = &auth_grant.server_identity_token {
                                    // Extrair o UUID do servidor do serverIdentityToken
                                    if let Some(server_uuid) = extract_jwt_subject(server_identity) {
                                        match request_server_auth_grant(identity_token, &server_uuid, session_token).await {
                                            Ok(grant) => Some(grant),
                                            Err(e) => {
                                                println!("⚠️ Falha ao gerar grant para servidor: {}", e);
                                                None
                                            }
                                        }
                                    } else {
                                        println!("⚠️ Não foi possível extrair UUID do serverIdentityToken");
                                        None
                                    }
                                } else {
                                    println!("⚠️ Sem serverIdentityToken, não podemos gerar grant para servidor");
                                    None
                                };

                                let auth_token = build_auth_token(
                                    Some(&access_token),
                                    server_grant.as_deref()
                                );
                                send.write_all(&auth_token).await?;
                            }
                            Err(e) => {
                                println!("❌ Falha ao obter accessToken: {}", e);
                                return Err(e);
                            }
                        }
                    }
                }
            }

            PACKET_SERVER_AUTH_TOKEN => {
                println!("🔐 Recebido ServerAuthToken - autenticação avançando!");
                if let Some(server_auth) = parse_server_auth_token(&payload) {
                    if server_auth.password_challenge.is_none() {
                        return Ok(());
                    } else {
                        println!("⚠️ Servidor pediu senha (PasswordChallenge), não implementado.");
                    }
                }
            }

            PACKET_CONNECT_ACCEPT => {
                println!("🎉 ConnectAccept - Conexão totalmente aceita!");
                return Ok(());
            }

            PACKET_PING => {
                // Se receber Ping durante o handshake, responde com Pong
                 println!("🏓 Ping recebido durante handshake, respondendo Pong...");
                 // Extrair ID e tempo do payload do ping (Offset 1 = ID, Offset 5 = Seconds, Offset 13 = Nanos)
                 if payload.len() >= 17 {
                     let ping_id = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
                     let seconds = i64::from_le_bytes([payload[5], payload[6], payload[7], payload[8], payload[9], payload[10], payload[11], payload[12]]);
                     let nanos = i32::from_le_bytes([payload[13], payload[14], payload[15], payload[16]]);

                     let pong = build_pong_packet(ping_id, seconds, nanos);
                     send.write_all(&pong).await?;
                 }
            }

            _ => {
                println!("❓ Pacote desconhecido durante Auth: {} (ID: {})", get_packet_name(packet_id), packet_id);
            }
        }
    }
}
