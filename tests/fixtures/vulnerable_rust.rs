use rsa::{RsaPrivateKey, RsaPublicKey};
use md5;
use sha1::Sha1;
use des::Des;
use rc4::Rc4;

fn generate_weak_key() {
    let mut rng = rand::thread_rng();
    let key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
    let hash = md5::compute(b"data");
    let sha = Sha1::new();
    let cipher = Des::new(&key_bytes);
    let rc = Rc4::new(&rc4_key);
}

fn openssl_usage() {
    let pkey = openssl::pkey::PKey::rsa(2048).unwrap();
    let md5_hash = openssl::hash::MessageDigest::md5();
    let sha1_hash = openssl::hash::MessageDigest::sha1();
}
