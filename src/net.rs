use std::sync::Arc;
use std::time::Duration;
use quinn::{ClientConfig, TransportConfig};
use rustls::RootCertStore;
use sha2::{Sha256, Digest};
use base64::{engine::general_purpose, Engine as _};

const MAX_UDP_PAYLOAD_SIZE: u16 = 1200;

#[derive(Debug)]
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

pub fn configure_client() -> (ClientConfig, String) {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let root_store = RootCertStore::empty();

    // Gerar certificado self-signed para mTLS (requerido pelo servidor Hytale)
    let subject_alt_names = vec!["hytale_client".to_string()];
    let certified_key = rcgen::generate_simple_self_signed(subject_alt_names).expect("Failed to generate client cert");

    let cert_der = certified_key.cert.der().clone();
    let priv_key = certified_key.signing_key.serialize_der();

    let mut hasher = Sha256::new();
    hasher.update(&cert_der.as_ref());
    let fingerprint = hasher.finalize();
    let x509_fingerprint = general_purpose::URL_SAFE_NO_PAD.encode(&fingerprint);

    println!("🔐 Certificado gerado, fingerprint: {}", x509_fingerprint);

    let cert_chain = vec![cert_der];
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(priv_key.into());

    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(cert_chain, key_der)
        .expect("Failed to configure client auth");

    tls_config.dangerous().set_certificate_verifier(SkipServerVerification::new());

    tls_config.alpn_protocols = vec![
        b"hytale/1".to_vec(),
    ];

    let mut transport_config = TransportConfig::default();
    transport_config.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    transport_config.keep_alive_interval(Some(Duration::from_secs(5)));
    transport_config.initial_mtu(MAX_UDP_PAYLOAD_SIZE);

    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
        .expect("Failed to create QUIC client config");

    let mut client_config = ClientConfig::new(Arc::new(quic_crypto));
    client_config.transport_config(Arc::new(transport_config));

    (client_config, x509_fingerprint)
}
