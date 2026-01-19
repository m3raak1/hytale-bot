//! Protocol encoding/decoding utilities

use std::error::Error;
use std::time::Duration;
use quinn::RecvStream;
use tokio::time::timeout;

type BoxError = Box<dyn Error + Send + Sync>;

// ============================================================================
// VarInt
// ============================================================================

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
            break;
        }
    }

    (value, bytes_read)
}

/// Escreve um VarInt no buffer
pub fn write_varint(buf: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
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

// ============================================================================
// Packet Reading
// ============================================================================

/// Lê um pacote do stream com timeout
pub async fn read_packet(recv: &mut RecvStream) -> Result<(u32, Vec<u8>), BoxError> {
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

// ============================================================================
// VarString Helpers
// ============================================================================

pub fn read_varstring_at(data: &[u8], var_block_start: usize, offset: i32) -> Option<String> {
    if offset < 0 { return None; }

    let pos = var_block_start + offset as usize;
    if pos >= data.len() { return None; }

    let (len, sz) = read_varint(&data[pos..]);
    let end = pos + sz + len as usize;
    if end > data.len() { return None; }

    String::from_utf8(data[pos + sz..end].to_vec()).ok()
}

pub fn read_varbytes_at(data: &[u8], var_block_start: usize, offset: i32) -> Option<Vec<u8>> {
    if offset < 0 { return None; }

    let pos = var_block_start + offset as usize;
    if pos >= data.len() { return None; }

    let (len, sz) = read_varint(&data[pos..]);
    let end = pos + sz + len as usize;
    if end > data.len() { return None; }

    Some(data[pos + sz..end].to_vec())
}

pub fn read_i32_le(data: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}
