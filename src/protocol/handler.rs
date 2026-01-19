use std::error::Error;
use quinn::{SendStream, RecvStream};
use serde::Deserialize;
use super::common::*;
use super::packets::*;
use reqwest;

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
    access_token: &str
) -> Result<(), Box<dyn Error + Send + Sync>> {
    loop {
        let (packet_id, payload) = read_packet(recv).await?;

        println!("\n📨 Recebido pacote {} ({} bytes)", get_packet_name(packet_id), payload.len());
        print_hex_dump(&[
            &(payload.len() as u32).to_le_bytes()[..],
            &packet_id.to_le_bytes()[..],
            &payload[..payload.len().min(64)],
        ].concat());

        match packet_id {
            PACKET_DISCONNECT => {
                println!("⛔ Servidor desconectou!");
                return Err("Desconectado pelo servidor".into());
            }

            PACKET_AUTH_GRANT => {
                println!("📋 Recebido AuthGrant - processando...");

                if let Some(auth_grant) = parse_auth_grant(&payload) {
                    println!("   Authorization Grant presente? {}", auth_grant.authorization_grant.is_some());

                    // Lógica simplificada: Se receber grant, devolve grant (não vamos implementar mTLS complexo agora a menos que falhe)
                    // O correto seria chamar a API da Hytale para trocar o Grant por um AccessToken real

                    if let Some(grant) = &auth_grant.authorization_grant {
                         println!("⚠️ Trocando Grant por Token via API (Simulado - Enviando de volta como fallback)");
                         // Por enquanto apenas devolvemos o token original + grant
                         let auth_token = build_auth_token(
                            Some(identity_token),
                            Some(grant)
                        );
                        send.write_all(&auth_token).await?;
                    } else {
                        // Fallback: Apenas reenvia identityToken
                        let auth_token = build_auth_token(Some(identity_token), None);
                        send.write_all(&auth_token).await?;
                    }
                }
            }

            PACKET_SERVER_AUTH_TOKEN => {
                println!("🔐 Recebido ServerAuthToken - autenticação avançando!");
                if let Some(server_auth) = parse_server_auth_token(&payload) {
                    if server_auth.password_challenge.is_none() {
                        println!("🎉 Autenticação completa sem password!");
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
