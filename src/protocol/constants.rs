//! Packet IDs and protocol constants

/// Packet IDs
pub const PACKET_CONNECT: u32 = 0;
pub const PACKET_DISCONNECT: u32 = 1;
pub const PACKET_PING: u32 = 2;
pub const PACKET_PONG: u32 = 3;
pub const PACKET_AUTH_GRANT: u32 = 11;
pub const PACKET_AUTH_TOKEN: u32 = 12;
pub const PACKET_SERVER_AUTH_TOKEN: u32 = 13;
pub const PACKET_CONNECT_ACCEPT: u32 = 14;

/// Protocol hash atual do Hytale (versão 2026.01.13)
pub const PROTOCOL_HASH: &[u8; 64] = b"6708f121966c1c443f4b0eb525b2f81d0a8dc61f5003a692a8fa157e5e02cea9";

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
