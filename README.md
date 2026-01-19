# Hytale Bot 🎮

Bot cliente para conexão com servidores Hytale usando o protocolo QUIC.

## 📁 Estrutura do Projeto

```
src/
├── main.rs              # Entry point
├── net.rs               # Configuração QUIC/TLS com mTLS
│
├── auth/                # Autenticação
│   ├── oauth.rs         # Login OAuth 2.0 + PKCE
│   ├── session.rs       # Criação de sessão de jogo
│   └── api.rs           # Chamadas API Hytale (grants, tokens)
│
├── protocol/            # Protocolo Hytale
│   ├── constants.rs     # Packet IDs e constantes
│   ├── codec.rs         # VarInt, leitura/escrita de pacotes
│   ├── packets.rs       # Builders de pacotes (Connect, Auth, Pong)
│   └── handler.rs       # Handler do fluxo de autenticação
│
└── utils/               # Utilitários
    ├── jwt.rs           # Parser de JWT
    └── debug.rs         # Hex dump para debug
```

## 🚀 Como Usar

### 1. Configurar credenciais

Edite `src/main.rs`:

```rust
const SERVER_ADDRESS: &str = "72.60.149.222";  // IP do servidor
const PORT: u16 = 5520;                         // Porta
const USERNAME: &str = "SeuNome";               // Seu username
const UUID: &str = "sua-uuid-aqui";             // Sua UUID
```

### 2. Compilar e executar

```bash
# Debug
cargo run

# Release (otimizado)
cargo run --release
```

## 📦 Dependências Principais

| Crate | Uso |
|-------|-----|
| `quinn` | Cliente QUIC |
| `rustls` | TLS 1.3 |
| `tokio` | Runtime async |
| `reqwest` | HTTP client |
| `warp` | Servidor local OAuth callback |
| `uuid` | Manipulação de UUIDs |
| `base64` | Encoding/decoding |
| `sha2` | Hash SHA-256 (PKCE, fingerprint) |

## 🔐 Fluxo de Autenticação

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Cliente   │     │  Hytale API  │     │   Servidor  │
└──────┬──────┘     └──────┬───────┘     └──────┬──────┘
       │                   │                    │
       │ 1. OAuth Login    │                    │
       │──────────────────>│                    │
       │   (PKCE flow)     │                    │
       │<──────────────────│                    │
       │   access_token    │                    │
       │                   │                    │
       │ 2. Create Session │                    │
       │──────────────────>│                    │
       │<──────────────────│                    │
       │ identity/session  │                    │
       │   tokens          │                    │
       │                   │                    │
       │ 3. Connect ───────────────────────────>│
       │   (QUIC + mTLS)   │                    │
       │                   │                    │
       │<─────────────────────────── AuthGrant  │
       │                   │                    │
       │ 4. Exchange Grant │                    │
       │──────────────────>│                    │
       │<──────────────────│                    │
       │   access_token    │                    │
       │                   │                    │
       │ 5. AuthToken ─────────────────────────>│
       │                   │                    │
       │<───────────────────── ServerAuthToken  │
       │                   │                    │
       │<───────────────────── ConnectAccept ✅ │
       │                   │                    │
```

## 📡 Pacotes do Protocolo

| ID | Nome | Direção |
|----|------|---------|
| 0 | Connect | C → S |
| 1 | Disconnect | S → C |
| 2 | Ping | S → C |
| 3 | Pong | C → S |
| 11 | AuthGrant | S → C |
| 12 | AuthToken | C → S |
| 13 | ServerAuthToken | S → C |
| 14 | ConnectAccept | S → C |

## 🔧 Formato de Pacote

```
┌────────────────┬────────────────┬─────────────────┐
│ Payload Length │   Packet ID    │     Payload     │
│   (4 bytes)    │   (4 bytes)    │   (N bytes)     │
│   Little End.  │   Little End.  │                 │
└────────────────┴────────────────┴─────────────────┘
```

## 📝 Notas

- Protocolo usa QUIC sobre UDP
- mTLS obrigatório (certificado self-signed é gerado automaticamente)
- VarInt encoding para strings (comprimento + bytes)
- Offsets usam -1 para campos null

## 📄 Licença

MIT
