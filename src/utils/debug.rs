//! Debug utilities

/// Imprime um hex dump formatado
#[allow(dead_code)]
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
