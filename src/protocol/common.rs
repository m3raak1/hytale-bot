use std::error::Error;
use std::time::Duration;
use quinn::RecvStream;
use tokio::time::timeout;

/// Packet IDs
pub const PACKET_CONNECT: u32 = 0;
pub const PACKET_DISCONNECT: u32 = 1;
pub const PACKET_PING: u32 = 2;
pub const PACKET_PONG: u32 = 3;
pub const PACKET_AUTH_GRANT: u32 = 11;
pub const PACKET_AUTH_TOKEN: u32 = 12;
pub const PACKET_SERVER_AUTH_TOKEN: u32 = 13;
pub const PACKET_CONNECT_ACCEPT: u32 = 14;

pub fn get_packet_name(id: u32) -> &'static str {
    match id {
        0 => "Connect",
        1 => "Disconnect",
        2 => "Ping",
        3 => "Pong",
        10 => "Status",
        11 => "AuthGrant",
        12 => "AuthToken",
        13 => "ServerAuthToken",
        14 => "ConnectAccept",
        15 => "PasswordResponse",
        16 => "PasswordAccepted",
        17 => "PasswordRejected",
        20 => "WorldSettings",
        _ => "Unknown",
    }
}

/// Lê um pacote do stream com timeout
pub async fn read_packet(recv: &mut RecvStream) -> Result<(u32, Vec<u8>), Box<dyn Error + Send + Sync>> {
    let mut header = [0u8; 8];

    match timeout(Duration::from_secs(10), recv.read_exact(&mut header)).await {
        Ok(Ok(())) => {},
        Ok(Err(e)) => return Err(format!("Erro lendo header: {}", e).into()),
        Err(_) => return Err("Timeout lendo header".into()),
    }

    let payload_len = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
    let packet_id = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);

    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        match timeout(Duration::from_secs(10), recv.read_exact(&mut payload)).await {
            Ok(Ok(())) => {},
            Ok(Err(e)) => return Err(format!("Erro lendo payload: {}", e).into()),
            Err(_) => return Err("Timeout lendo payload".into()),
        }
    }

    Ok((packet_id, payload))
}

/// Lê um VarInt do buffer, retorna (valor, bytes_consumidos)
pub fn read_varint(data: &[u8]) -> (u32, usize) {
    let mut value: u32 = 0;
    let mut shift = 0;
    let mut bytes_read = 0;

    for &byte in data {
        bytes_read += 1;
        value |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 35 {
            break; // Overflow protection
        }
    }

    (value, bytes_read)
}

/// Helper para escrever VarInt
pub fn write_varint(buf: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80; // Set continuation bit
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Calcula o tamanho de um VarInt
pub fn varint_size(value: u32) -> usize {
    if value < 128 { 1 }
    else if value < 16384 { 2 }
    else if value < 2097152 { 3 }
    else if value < 268435456 { 4 }
    else { 5 }
}

pub fn print_hex_dump(data: &[u8]) {
    println!("┌─────────────────────────────────────────────────────────┐");
    for (i, chunk) in data.chunks(16).enumerate() {
        let hex: String = chunk
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");

        let ascii: String = chunk
            .iter()
            .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
            .collect();

        println!("│ {:04X}: {:48} │ {} │", i * 16, hex, ascii);
    }
    println!("└─────────────────────────────────────────────────────────┘");
}
