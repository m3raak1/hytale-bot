use uuid::Uuid;
use super::common::{PACKET_CONNECT, write_varint, varint_size, PACKET_AUTH_TOKEN, PACKET_PONG};

/// Protocol hash atual do Hytale (versão 2026.01.13)
const PROTOCOL_HASH: &[u8; 64] = b"6708f121966c1c443f4b0eb525b2f81d0a8dc61f5003a692a8fa157e5e02cea9";

/// Client types
#[repr(u8)]
pub enum ClientType {
    Game = 0,
    Editor = 1,
}

pub fn build_connect_packet_with_token(username: &str, uuid: Uuid, identity_token: &str) -> Vec<u8> {

    let identity_token = Some(identity_token);
    let mut payload = Vec::with_capacity(1024);

    // ========== FIXED BLOCK (102 bytes) ==========

    // Offset 0: nullBits
    let null_bits: u8 = if identity_token.is_some() { 0x02 } else { 0x00 };
    payload.push(null_bits);

    // Offset 1-64: protocolHash (64 bytes ASCII fixo)
    payload.extend_from_slice(PROTOCOL_HASH);

    // Offset 65: clientType (Game = 0)
    payload.push(ClientType::Game as u8);

    // Offset 66-81: UUID (16 bytes)
    // O UUID é armazenado como dois i64 em Big Endian
    let uuid_bytes = uuid.as_bytes();
    payload.extend_from_slice(uuid_bytes);

    // ========== VARIABLE OFFSETS (20 bytes) ==========

    // Calcular offsets dinamicamente
    let mut current_offset: i32 = 0;

    // Username será primeiro no variable block
    let username_bytes = username.as_bytes();
    if username_bytes.len() > 16 {
        panic!("Username muito longo! Máximo 16 caracteres.");
    }
    let username_var_size = varint_size(username_bytes.len() as u32) + username_bytes.len();

    // Offset 82-85: languageOffset (-1 = null)
    payload.extend_from_slice(&(-1i32).to_le_bytes());

    // Offset 86-89: identityTokenOffset
    let identity_token_offset: i32;
    let token_bytes: &[u8];
    if let Some(token) = identity_token {
        // identityToken vem DEPOIS do username no variable block
        identity_token_offset = current_offset + username_var_size as i32;
        token_bytes = token.as_bytes();
    } else {
        identity_token_offset = -1;
        token_bytes = &[];
    }
    payload.extend_from_slice(&identity_token_offset.to_le_bytes());

    // Offset 90-93: usernameOffset (0 = início do variable block)
    payload.extend_from_slice(&current_offset.to_le_bytes());

    // Offset 94-97: referralDataOffset (-1 = null)
    payload.extend_from_slice(&(-1i32).to_le_bytes());

    // Offset 98-101: referralSourceOffset (-1 = null)
    payload.extend_from_slice(&(-1i32).to_le_bytes());

    // ========== VARIABLE BLOCK (inicia offset 102) ==========

    // Username como VarString (VarInt length + bytes)
    write_varint(&mut payload, username_bytes.len() as u32);
    payload.extend_from_slice(username_bytes);

    // IdentityToken como VarString (se presente)
    if identity_token.is_some() {
        write_varint(&mut payload, token_bytes.len() as u32);
        payload.extend_from_slice(token_bytes);
    }

    // ========== FRAME HEADER ==========
    // Conforme PacketIO.java:
    // [Payload Length (u32 LE)] [Packet ID (u32 LE)] [Payload]
    // O Length é APENAS o tamanho do payload (não inclui o ID).

    let mut frame = Vec::with_capacity(8 + payload.len());

    // Payload length (4 bytes LE)
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());

    // Packet ID (4 bytes LE) - Connect = 0
    frame.extend_from_slice(&PACKET_CONNECT.to_le_bytes());

    // Payload
    frame.extend(payload);

    frame
}

pub fn build_auth_token(access_token: Option<&str>, authorization_grant: Option<&str>) -> Vec<u8> {
    let mut payload = Vec::new();

    let mut null_bits: u8 = 0;
    if access_token.is_some() { null_bits |= 1; }
    if authorization_grant.is_some() { null_bits |= 2; }

    payload.push(null_bits);

    // Offsets (8 bytes - 2 ints)
    let mut current_offset: i32 = 0;

    // Access Token Offset
    let access_token_bytes = access_token.unwrap_or("").as_bytes();
    let access_token_start = if access_token.is_some() {
        let start = current_offset;
        // VarInt size + String bytes
        current_offset += varint_size(access_token_bytes.len() as u32) as i32 + access_token_bytes.len() as i32;
        start
    } else {
        -1
    };
    payload.extend_from_slice(&access_token_start.to_le_bytes());

    // Grant Offset
    let grant_bytes = authorization_grant.unwrap_or("").as_bytes();
    let grant_start = if authorization_grant.is_some() {
        current_offset // Grant starts right after accessToken
    } else {
        -1
    };
    payload.extend_from_slice(&grant_start.to_le_bytes());

    // Variable Block
    if let Some(token) = access_token {
        write_varint(&mut payload, token.as_bytes().len() as u32);
        payload.extend_from_slice(token.as_bytes());
    }

    if let Some(grant) = authorization_grant {
        write_varint(&mut payload, grant.as_bytes().len() as u32);
        payload.extend_from_slice(grant.as_bytes());
    }

    // Frame (Standard Hytale/PacketIO)
    let mut frame = Vec::with_capacity(8 + payload.len());
    // Length (u32 LE)
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    // ID (u32 LE)
    frame.extend_from_slice(&PACKET_AUTH_TOKEN.to_le_bytes());
    // Payload
    frame.extend(payload);

    frame
}


/// Constrói um pacote Pong em resposta a um Ping
pub fn build_pong_packet(ping_id: u32, ping_time_seconds: i64, ping_time_nanos: i32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(32);

    // nullBits (1 byte)
    payload.push(0x00);

    // id (4 bytes LE) - mesmo ID do ping
    payload.extend_from_slice(&ping_id.to_le_bytes());

    // time - InstantData (12 bytes)
    payload.extend_from_slice(&ping_time_seconds.to_le_bytes()); // 8 bytes
    payload.extend_from_slice(&ping_time_nanos.to_le_bytes());   // 4 bytes

    // type - PongType (1 byte): Raw=0, Direct=1, Tick=2
    payload.push(0); // Raw

    // packetQueueSize (2 bytes LE)
    payload.extend_from_slice(&0u16.to_le_bytes());

    // Frame
    let mut frame = Vec::with_capacity(8 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&PACKET_PONG.to_le_bytes());
    frame.extend(payload);

    frame
}
