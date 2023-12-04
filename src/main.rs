use aes_gcm::aead::generic_array::{typenum::U16, typenum::U32, GenericArray};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, Tag};
use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use ed25519_dalek::{Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use hex::{FromHex, ToHex};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs;
use std::str;

mod encrypt;
use encrypt::encrypt_lic;

#[derive(Deserialize, Serialize, Debug)]
struct LicenseFile<'a> {
    enc: &'a str,
    sig: &'a str,
    alg: &'a str,
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short = 'l', long, value_parser)]
    license_key: String,

    #[clap(short = 'k', long, value_parser)]
    public_key: String,

    #[clap(short = 'p', long, value_parser)]
    path: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let encrypt = false;

    if encrypt {
        let _ = encrypt_lic();
    } else {
        let args = Args::parse();
        let license_key: &str = &args.license_key;
        let public_key: &str = &args.public_key;
        let lic_path: &str = &args.path;
    
        let result = decrypt_license(license_key, public_key, lic_path).unwrap();
    }
    

    Ok(())
}


// cargo run -- -p license/test_license.lic \
//    -k "0ae2186a66ea57019e66f296cac767de1f200d99dd879dd6dff19644bb3d3082" \
//    -l "988214-879010-F1185E-B37E91-E53AF5-V3"

// cargo run -- -p examples/license.lic \
//   -k "e8601e48b69383ba520245fd07971e983d06d22c4257cfd82304601479cee788" \
//   -l "988214-879010-F1185E-B37E91-E53AF5-V3"

fn decrypt_license(
    license_key: &str,
    public_key: &str,
    lic_path: &str,
) -> Result<(), Box<dyn Error>> {

    println!("chegou");
    // Parse the hex-encoded public key.
    let public_key: VerifyingKey = match <[u8; PUBLIC_KEY_LENGTH]>::from_hex(public_key) {
        Ok(bytes) => VerifyingKey::from_bytes(&bytes)?,
        Err(_) => return Err("failed to parse public key".into()),
    };

    let cert = match fs::read_to_string(lic_path) {
        Ok(content) => content,
        Err(_) => return Err("failed to import license file".into()),
    };

    // Extract the encoded payload from the license file.
    let enc = cert
        .replace("-----BEGIN LICENSE FILE-----", "")
        .replace("-----END LICENSE FILE-----", "")
        .replace('\n', "");

    // Decode the payload.
    let payload = match general_purpose::STANDARD.decode(enc) {
        Ok(bytes) => String::from_utf8(bytes)?,
        Err(_) => return Err("failed to decode license file".into()),
    };

    println!("payload - {:?}", payload.as_str());
    // Parse the payload.
    let lic: LicenseFile = match serde_json::from_str(payload.as_str()) {
        Ok(json) => json,
        Err(_) => return Err("failed to parse license file".into()),
    };

    println!("json - {:?}", lic);
    // Assert algorithm is supported.
    match lic.alg {
        "aes-256-gcm+ed25519" => (),
        _ => return Err("algorithm is not supported".into()),
    }

    // Verify the license file's signature.
    println!("lic.sig : {:?}", general_purpose::STANDARD.decode(lic.sig)?.len());
    let msg = format!("license/{}", lic.enc);
    let sig: [u8; SIGNATURE_LENGTH] = match general_purpose::STANDARD.decode(lic.sig)?.try_into() {
        Ok(sig) => sig,
        Err(err) => return Err(format!("signature format is invalid: - Err: {:?}", err).into()),
    };

    match public_key.verify(msg.as_bytes(), &sig.into()) {
        Ok(_) => (),
        Err(_) => return Err("license file is invalid".into()),
    }
    println!("chegou 2");
    // Print license file.
    println!("license file was successfully verified!");
    println!("  > {}", serde_json::to_string_pretty(&lic).unwrap());

    // Hash the license key to obtain decryption key.
    let mut sha = Sha256::new();

    sha.update(license_key.as_bytes());

    let digest: GenericArray<u8, U32> = sha.finalize();

    // Parse the encrypted data.
    let data: Vec<_> = lic
        .enc
        .trim()
        .split(".")
        .map(|v| {
            general_purpose::STANDARD
                .decode(v)
                .expect("failed to parse encrypted data")
        })
        .collect();

    println!("TAG content - {:?}", data[2]);

    // Set up data and AES-GCM.
    let mut ciphertext = Vec::from(data[0].as_slice());
    let nonce = Nonce::from_slice(data[1].as_slice());
    let tag: &GenericArray<u8, U16> = Tag::from_slice(data[2].as_slice());
    let key: &GenericArray<u8, U32> = GenericArray::from_slice(&digest);
    let aes = Aes256Gcm::new_from_slice(key)?;

    // Concat authentication tag with ciphertext.
    ciphertext.extend_from_slice(tag);

    // Decrypt the license file.
    let plaintext = match aes.decrypt(nonce, ciphertext.as_ref()) {
        Ok(plaintext) => String::from_utf8(plaintext)?,
        Err(_) => return Err("failed to decrypt license file".into()),
    };

    // Print decrypted data.
    let obj: serde_json::Value = serde_json::from_str(&plaintext).unwrap();

    println!("license file was successfully decrypted!");
    println!("  > {}", serde_json::to_string_pretty(&obj).unwrap());

    Ok(())
}
