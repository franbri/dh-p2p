/*
 * Device authentication for P2P channel creation, ported from helpers.py.
 * Required by devices that answer `/device/{SN}/p2p-channel` with 403.
 */
use aes::cipher::{KeyIvInit, StreamCipher};
use base64::Engine;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use sha2::Sha256;

use crate::util::Result;

pub const DEFAULT_RANDSALT: &str = "5daf91fc5cfc1be8e081cfb08f792726";
const IV: &[u8; 16] = b"2z52*lk9o6HRyJrf";

type Aes256Ofb = ofb::Ofb<aes::Aes256>;

pub struct DeviceAuth {
    username: String,
    randsalt: String,
    key: Vec<u8>,
}

impl DeviceAuth {
    pub fn new(username: &str, password: &str, randsalt: &str) -> DeviceAuth {
        let digest = Md5::digest(format!("{}:Login to {}:{}", username, randsalt, password));
        let key = digest
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<String>()
            .into_bytes();

        DeviceAuth {
            username: username.to_string(),
            randsalt: randsalt.to_string(),
            key,
        }
    }

    pub fn nonce() -> String {
        (rand::random::<u32>() & 0x7FFF_FFFF).to_string()
    }

    fn cipher(&self, nonce: &str) -> Aes256Ofb {
        let mut dk = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(&self.key, nonce.as_bytes(), 20000, &mut dk);
        Aes256Ofb::new(&dk.into(), IV.into())
    }

    pub fn encrypt(&self, nonce: &str, data: &str) -> String {
        let mut buf = data.as_bytes().to_vec();
        self.cipher(nonce).apply_keystream(&mut buf);
        base64::engine::general_purpose::STANDARD.encode(buf)
    }

    pub fn decrypt(&self, nonce: &str, data: &str) -> Result<String> {
        let mut buf = base64::engine::general_purpose::STANDARD.decode(data.trim())?;
        self.cipher(nonce).apply_keystream(&mut buf);
        Ok(String::from_utf8(buf)?)
    }

    fn sign(&self, nonce: &str, curdate: i64, payload: &str) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.key).unwrap();
        mac.update(format!("{}{}{}", nonce, curdate, payload).as_bytes());
        base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
    }

    /**
     * XML fragment authenticating a request, `payload` is signed along
     */
    pub fn xml(&self, nonce: &str, payload: &str) -> String {
        let curdate = chrono::Utc::now().timestamp();
        let auth = self.sign(nonce, curdate, payload);

        format!(
            "<CreateDate>{}</CreateDate>\
             <DevAuth>{}</DevAuth>\
             <Nonce>{}</Nonce>\
             <RandSalt>{}</RandSalt>\
             <UserName>{}</UserName>",
            curdate, auth, nonce, self.randsalt, self.username
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // vectors computed with helpers.py
    #[test]
    fn matches_python() {
        let auth = DeviceAuth::new("admin", "secret", DEFAULT_RANDSALT);
        assert_eq!(auth.key, b"0458DB44DB317937300C1B4DE606F033");
        assert_eq!(
            auth.encrypt("12345", "192.168.1.10:37777"),
            "FHZK0Nhjfq70BCqBHpfve/be"
        );
        assert_eq!(
            auth.sign("12345", 1700000000, "payload"),
            "TL4VJubgh8tJwFoDr5WVVTWKbzbka7/vGTQ6HHEQuxY="
        );
    }

    #[test]
    fn encrypt_roundtrip() {
        let auth = DeviceAuth::new("admin", "secret", DEFAULT_RANDSALT);
        let enc = auth.encrypt("12345", "192.168.1.10:37777");
        assert_eq!(auth.decrypt("12345", &enc).unwrap(), "192.168.1.10:37777");
    }
}
