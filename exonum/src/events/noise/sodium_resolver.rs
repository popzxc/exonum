#![allow(unsafe_code)]
#![allow(missing_debug_implementations, missing_docs)]

use byteorder::{ByteOrder, LittleEndian};
use rand::{thread_rng, Rng};
use snow::params::{CipherChoice, DHChoice, HashChoice};
pub use snow::types::{Cipher, Dh, Hash, Random};
use snow::{CryptoResolver, DefaultResolver};
use std::{mem, fmt};

use sodiumoxide::crypto::aead::chacha20poly1305 as sodium_chacha20poly1305;
use sodiumoxide::crypto::hash::sha256 as sodium_sha256;
use sodiumoxide::crypto::scalarmult::curve25519 as sodium_curve25519;

use libsodium_sys::{crypto_generichash_state, crypto_generichash_init, crypto_generichash_update, crypto_generichash_final, crypto_generichash_statebytes};
use libsodium_sys::{crypto_hash_sha256_state, crypto_hash_sha256_init, crypto_hash_sha256_update, crypto_hash_sha256_final};

/// a
pub struct SodiumResolver {
    parent: DefaultResolver,
}

impl SodiumResolver {
    /// a
    pub fn new() -> Self {
        SodiumResolver {
            parent: DefaultResolver,
        }
    }
}

impl CryptoResolver for SodiumResolver {
    fn resolve_rng(&self) -> Option<Box<Random + Send>> {
        Some(Box::new(SodiumRandom::default()))
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<Dh + Send>> {
        match *choice {
            DHChoice::Curve25519 => Some(Box::new(SodiumDh25519::default())),
            _ => self.parent.resolve_dh(choice),
        }
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<Hash + Send>> {
        match *choice {
            HashChoice::SHA256 => Some(Box::new(SodiumSha256::default())),
            HashChoice::Blake2s => Some(Box::new(SodiumBlake2s::default())),
            _ => self.parent.resolve_hash(choice),
        }
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<Cipher + Send>> {
        match *choice {
            CipherChoice::ChaChaPoly => Some(Box::new(SodiumChaChaPoly::default())),
            _ => self.parent.resolve_cipher(choice),
        }
    }
}

// Random data generator.
struct SodiumRandom;

impl Default for SodiumRandom {
    fn default() -> SodiumRandom {
        SodiumRandom {}
    }
}

impl Random for SodiumRandom {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        let bytes: Vec<u8> = thread_rng().gen_iter::<u8>().take(out.len()).collect();
        out.copy_from_slice(&bytes);
    }
}

// Elliptic curve 25519.
/// a
pub struct SodiumDh25519 {
    privkey: sodium_curve25519::Scalar,
    pubkey: sodium_curve25519::GroupElement,
}

impl Default for SodiumDh25519 {
    fn default() -> SodiumDh25519 {
        SodiumDh25519 {
            privkey: sodium_curve25519::Scalar([0; 32]),
            pubkey: sodium_curve25519::GroupElement([0; 32]),
        }
    }
}

impl Dh for SodiumDh25519 {
    fn name(&self) -> &'static str {
        "25519"
    }

    fn pub_len(&self) -> usize {
        32
    }

    fn priv_len(&self) -> usize {
        32
    }

    fn set(&mut self, privkey: &[u8]) {
        self.privkey = sodium_curve25519::Scalar::from_slice(privkey)
            .expect("Can't construct private key for Dh25519");
        self.pubkey = sodium_curve25519::scalarmult_base(&self.privkey);
    }

    fn generate(&mut self, rng: &mut Random) {
        let mut privkey_bytes = [0; 32];
        rng.fill_bytes(&mut privkey_bytes);
        privkey_bytes[0] &= 248;
        privkey_bytes[31] &= 127;
        privkey_bytes[31] |= 64;
        self.privkey = sodium_curve25519::Scalar::from_slice(&privkey_bytes)
            .expect("Can't construct private key for Dh25519");
        self.pubkey = sodium_curve25519::scalarmult_base(&self.privkey);
    }

    fn pubkey(&self) -> &[u8] {
        &self.pubkey[0..32]
    }

    fn privkey(&self) -> &[u8] {
        &self.privkey[0..32]
    }

    fn dh(&self, pubkey: &[u8], out: &mut [u8]) {
        let pubkey = sodium_curve25519::GroupElement::from_slice(&pubkey[0..32])
            .expect("Can't construct public key for Dh25519");
        let result =
            sodium_curve25519::scalarmult(&self.privkey, &pubkey).expect("Can't calculate dh");

        out[..32].copy_from_slice(&result[0..32]);
    }
}

// Chacha20poly1305 cipher.
/// a.
pub struct SodiumChaChaPoly {
    key: sodium_chacha20poly1305::Key,
}

impl Default for SodiumChaChaPoly {
    fn default() -> SodiumChaChaPoly {
        SodiumChaChaPoly {
            key: sodium_chacha20poly1305::Key([0; 32]),
        }
    }
}

impl Cipher for SodiumChaChaPoly {
    fn name(&self) -> &'static str {
        "ChaChaPoly"
    }

    fn set(&mut self, key: &[u8]) {
        self.key = sodium_chacha20poly1305::Key::from_slice(&key[0..32])
            .expect("Can't get key for ChaChaPoly");
    }

    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
        let mut nonce_bytes = [0u8; 8];
        LittleEndian::write_u64(&mut nonce_bytes[..], nonce);
        let nonce = sodium_chacha20poly1305::Nonce(nonce_bytes);

        let buf = sodium_chacha20poly1305::seal(plaintext, Some(authtext), &nonce, &self.key);

        out[..buf.len()].copy_from_slice(&buf);
        buf.len()
    }

    fn decrypt(
        &self,
        nonce: u64,
        authtext: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, ()> {
        let mut nonce_bytes = [0u8; 8];
        LittleEndian::write_u64(&mut nonce_bytes[..], nonce);
        let nonce = sodium_chacha20poly1305::Nonce(nonce_bytes);

        let result = sodium_chacha20poly1305::open(ciphertext, Some(authtext), &nonce, &self.key);

        match result {
            Ok(ref buf) => {
                out[..buf.len()].copy_from_slice(&buf);
                Ok(buf.len())
            }
            Err(_) => Err(()),
        }
    }
}

// #[derive(Debug, Default)]
pub struct SodiumBlake2s{ 
    handle: Vec<u8>,
    key: [u8; 64],
}

impl SodiumBlake2s {
    fn inner(&mut self) -> *mut crypto_generichash_state{
        unsafe { mem::transmute::<*mut u8, *mut crypto_generichash_state>(self.handle.as_mut_ptr()) }
    }

    fn set_key(&mut self, key: [u8; 64]) {
        self.key = key;
    }
}

impl Default for SodiumBlake2s {
    fn default() -> SodiumBlake2s {
        unsafe {
            let key = [0; 64];
            let mut st = vec![0u8; crypto_generichash_statebytes()];
            let pst = mem::transmute::<*mut u8, *mut crypto_generichash_state>(st.as_mut_ptr());
            crypto_generichash_init(pst, key.as_ptr(), key.len(), 64);
            SodiumBlake2s{ handle: st, key: key}
        }
    }
}

impl fmt::Debug for SodiumBlake2s {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "boop")
    }
}

impl Hash for SodiumBlake2s {
    fn name(&self) -> &'static str {
        "SodiumBlake2s"
    }

    fn block_len(&self) -> usize {
        128
    }

    fn hash_len(&self) -> usize {
        64
    }

    fn reset(&mut self) {
        unsafe {
            crypto_generichash_init(self.inner(), self.key.as_ptr(), self.key.len(), 64);
        }
    }

    fn input(&mut self, data: &[u8]) {
        unsafe {
            crypto_generichash_update(self.inner(), data.as_ptr(), data.len() as u64);
        }
    }

    fn result(&mut self, out: &mut [u8]) {
        unsafe {
            crypto_generichash_final(self.inner(), out.as_mut_ptr(), 64);
        }
    }
}

pub struct SodiumSha256(Vec<u8>);

impl SodiumSha256 {
    fn inner(&mut self) -> *mut crypto_hash_sha256_state {
        unsafe { mem::transmute::<*mut u8, *mut crypto_hash_sha256_state>(self.0.as_mut_ptr()) }
    }
}

impl Default for SodiumSha256 {
    fn default() -> SodiumSha256 {
            let st = vec![0u8; mem::size_of::<crypto_hash_sha256_state>()];
            // let state = crypto_hash_sha256_state { state: [0; 8], count: [0; 2], buf: [0; 64]};
            SodiumSha256(st)
    }
}

impl fmt::Debug for SodiumSha256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "boop")
    }
}

impl Hash for SodiumSha256 {
    fn name(&self) -> &'static str {
        "Sha256"
    }

    fn block_len(&self) -> usize {
        64
    }

    fn hash_len(&self) -> usize {
        32
    }

    fn reset(&mut self) {
        unsafe {
            crypto_hash_sha256_init(self.inner());
        }
    }

    fn input(&mut self, data: &[u8]) {
        unsafe {
            crypto_hash_sha256_update(self.inner(), data.as_ptr(), data.len() as u64);
        }
    }

    fn result(&mut self, out: &mut [u8]) {
        unsafe {

            crypto_hash_sha256_final(self.inner(), out as *mut [u8] as *mut [u8; 32]);
        }
        // let digest = self.0.clone().finalize();
        // out[..32].copy_from_slice(digest.as_ref());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    #[test]
    fn test_curve25519() {
        // Values are cited from RFC-7748: 5.2.  Test Vectors.
        let mut keypair: SodiumDh25519 = Default::default();
        let scalar = Vec::<u8>::from_hex(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        ).unwrap();
        keypair.set(&scalar);
        let public = Vec::<u8>::from_hex(
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        ).unwrap();
        let mut output = [0u8; 32];
        keypair.dh(&public, &mut output);

        assert_eq!(
            output,
            Vec::<u8>::from_hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
                .unwrap()
                .as_ref()
        );
    }

    #[test]
    fn test_blake2s_digest() {
        let input = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                            0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
                            0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
                            0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                            0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53,
                            0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
                            0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
                            0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
                            0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83,
                            0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
                            0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                            0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3,
                            0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
                            0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
                            0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
                            0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3,
                            0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
                            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
                            0xfc, 0xfd, 0xfe];
        let output = [0x14, 0x27, 0x09, 0xd6, 0x2e, 0x28, 0xfc, 0xcc, 0xd0, 0xaf, 0x97,
                             0xfa, 0xd0, 0xf8, 0x46, 0x5b, 0x97, 0x1e, 0x82, 0x20, 0x1d, 0xc5,
                             0x10, 0x70, 0xfa, 0xa0, 0x37, 0x2a, 0xa4, 0x3e, 0x92, 0x48, 0x4b,
                             0xe1, 0xc1, 0xe7, 0x3b, 0xa1, 0x09, 0x06, 0xd5, 0xd1, 0x85, 0x3d,
                             0xb6, 0xa4, 0x10, 0x6e, 0x0a, 0x7b, 0xf9, 0x80, 0x0d, 0x37, 0x3d,
                             0x6d, 0xee, 0x2d, 0x46, 0xd6, 0x2e, 0xf2, 0xa4, 0x61];
        let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                               0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                               0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
                               0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
                               0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
                               0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f];

        let mut hasher = SodiumBlake2s::default();

        hasher.set_key(key);

        hasher.reset();

        let mut output_gotten = [0; 64];

        hasher.input(&input);
        hasher.result(&mut output_gotten);

        assert!(&output[..] == &output_gotten[..]);
    }
}
