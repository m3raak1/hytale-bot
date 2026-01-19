//! JWT parsing utilities

use base64::{engine::general_purpose, Engine as _};

/// Extrai o "sub" (UUID) de um JWT sem validar a assinatura
pub fn extract_jwt_subject(jwt: &str) -> Option<String> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() < 2 {
        println!("⚠️ JWT inválido - menos de 2 partes");
        return None;
    }

    let payload_bytes = decode_jwt_payload(parts[1])?;
    let payload_str = String::from_utf8(payload_bytes).ok()?;

    println!("📄 JWT payload: {}", &payload_str[..payload_str.len().min(200)]);

    let json: serde_json::Value = serde_json::from_str(&payload_str).ok()?;
    let sub = json.get("sub").and_then(|v| v.as_str()).map(|s| s.to_string());
    println!("🔑 Servidor UUID extraído: {:?}", sub);
    sub
}

fn decode_jwt_payload(payload_b64: &str) -> Option<Vec<u8>> {
    general_purpose::URL_SAFE_NO_PAD.decode(payload_b64)
        .or_else(|_| general_purpose::URL_SAFE.decode(payload_b64))
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(payload_b64))
        .or_else(|_| general_purpose::STANDARD.decode(payload_b64))
        .ok()
}
