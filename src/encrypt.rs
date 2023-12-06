use aes_gcm::aead::generic_array::{typenum::U16, typenum::U32, GenericArray};
use std::error::Error;
use std::fs::File;
use base64::{engine::general_purpose, Engine as _, alphabet::STANDARD};
use std::io::{BufRead, BufReader, Write};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key // Or `Aes128Gcm`
};
use sha2::{Sha256, Sha512, Digest};
use hex::{FromHex, ToHex};
use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Signer, SECRET_KEY_LENGTH, PUBLIC_KEY_LENGTH};



use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct License {
    name: String,
    num_var: usize
}

#[derive(Serialize, Deserialize, Debug)]
struct LicenseModel {
    enc: String,
    sig: String,
    alg: String
}

pub fn encrypt_lic() -> Result<(), Box<dyn Error>> {
    let path = "license/test_license.lic";

    {
        let license = serde_json::json!(License {
            name: "teste".to_owned(),
            num_var: 1
        });

        println!("{:}", &license);

        let mut output = File::create(path)?;

        let txt_license = license.to_string();

        let texto = "988214-879010-F1185E-B37E91-E53AF5-V3";

        let mut hasher = Sha256::new();
        hasher.update(texto.as_bytes());
        let digest = hasher.finalize();

        let key: &GenericArray<u8, U32> = GenericArray::from_slice(&digest);
        let aes = Aes256Gcm::new_from_slice(key)?;

        // let key = Aes256Gcm::generate_key(OsRng);
        // // Transformed from a byte array:
        // let key: &[u8; 32] = &[42; 32];
        // let key: &Key<Aes256Gcm> = key.into();

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
        let ciphertext = aes.encrypt(&nonce, txt_license.as_bytes().as_ref()).unwrap();
        let cipherclone = ciphertext.clone();
        let tag = &cipherclone[..4];


        let cipher64 = general_purpose::STANDARD.encode(ciphertext);
        let nonce64 = general_purpose::STANDARD.encode(nonce);
        let tag64 = general_purpose::STANDARD.encode(tag);

        let mut cipher_full: String = String::new();
        cipher_full.push_str(&cipher64);
        cipher_full.push_str(".");
        cipher_full.push_str(&nonce64);
        cipher_full.push_str(".");
        cipher_full.push_str(&tag64);


        let enc = general_purpose::STANDARD.encode(cipher_full);

        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);

        let public = hex::encode( &signing_key.verifying_key().to_bytes());
        let private = hex::encode( &signing_key.to_bytes());

        println!("{:?} - {:?}", private, public);

        let signature: Signature = signing_key.sign(format!("license/{}", enc).as_bytes());
        // let signature: Signature = signing_key.sign( enc.as_bytes());
        let sig64 = general_purpose::STANDARD.encode(signature.to_bytes());
        println!("signature size: {}", signature.to_bytes().len());


        let lic: LicenseModel = LicenseModel{
            enc: enc,
            sig: sig64,
            alg: "aes-256-gcm+ed25519".to_string()
        };

        let lic64 = general_purpose::STANDARD.encode(serde_json::json!(lic).to_string());

        let full_license = append_header_footer(lic64)?;

        output.write_all(full_license.as_bytes())?;
        // write!(output, txt_license);
    }

    let input = File::open(path)?;
    let buffered = BufReader::new(input);

    for line in buffered.lines() {
        println!("{}", line?);
    }

    Ok(())
}


fn append_header_footer (body: String) -> Result<String, String> {

    let lic_type = "LICENSE";

    let header = format!("-----BEGIN {lic_type} FILE-----");
    let footer = format!("-----END {lic_type} FILE-----");

    let mut full_body: String = String::new();

    full_body.push_str(header.as_str());
    full_body.push_str("\n");
    full_body.push_str(body.as_str());
    full_body.push_str("\n");
    full_body.push_str(footer.as_str());

    Ok(full_body)

}
