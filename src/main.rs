use rand::{Rng, rng};
use solana_sdk::{signature::{Keypair, Signer}, signer::SeedDerivable};
use bs58;
use rayon::prelude::*;
use std::sync::{Arc, Mutex};
use tokio::task;
use mongodb::{Client, options::ClientOptions, Collection};
use mongodb::bson::doc;
use aes::Aes256;
use cipher::{KeyIvInit, block_padding::Pkcs7, BlockEncryptMut, BlockSizeUser};
use hex;
use std::str;
use cbc::Encryptor;


const IV_LENGTH: usize = 16;

#[tokio::main]
async fn main() {
    let client_options = ClientOptions::parse("mongodb+srv://....").await.unwrap();
    let client = Client::with_options(client_options).unwrap();
    let db = client.database("keygen");
    let collection = db.collection("keys");

    let results = Arc::new(Mutex::new(Vec::new()));
    let target_suffix = "pkin".to_string();
    let encryption_key = "624ab98e7c4306907b24650b2f6196bae5d7b1a1ad31e87b5f09765c626c5632";
    let results_clone = Arc::clone(&results);
    let collection_clone = collection.clone();

    task::spawn(async move {
        generate_keypair_parallel(&target_suffix, results_clone, collection_clone, encryption_key).await;
    });

    // Simulate doing other work in the main thread
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        let results = results.lock().unwrap();
        println!("found keys: {:?}", *results);
    }
}

fn generate_keypair(target_suffix: &str) -> Option<(String, String)> {
    let seed: [u8; 32] = rng().random();

    if let Ok(keypair) = Keypair::from_seed(&seed) {
        let public_key = keypair.pubkey().to_string();

        if public_key.ends_with(target_suffix) {
            let private_key = bs58::encode(keypair.to_bytes()).into_string();
            return Some((public_key, private_key));
        }
    }
    None
}

async fn generate_keypair_parallel(target_suffix: &str, results: Arc<Mutex<Vec<(String, String)>>>, collection: Collection<mongodb::bson::Document>, encryption_key: &str) {
    loop {
        let batch: Vec<(String, String)> = (0..100_000).into_par_iter().filter_map(|_| generate_keypair(target_suffix)).collect();

        if !batch.is_empty() {
            {
                let mut results = results.lock().unwrap();
                results.extend(batch.clone());
            }

            // Save to MongoDB asynchronously
            let docs: Vec<_> = batch.into_iter().map(|(public_key, private_key)| {
                let encrypted_private_key = encrypt(&private_key, encryption_key);
                doc! {
                    "public_key": public_key,
                    "private_key": encrypted_private_key,
                }
            }).collect();

            let collection_clone = collection.clone();
            tokio::spawn(async move {
                if let Err(e) = collection_clone.insert_many(docs).await {
                    eprintln!("Failed to insert documents: {}", e);
                }
            });
        }
    }
}

pub fn encrypt(private_key: &str, encryption_key: &str) -> String {
    let key_bytes = hex::decode(encryption_key).expect("Invalid hex encryption key");
    assert_eq!(key_bytes.len(), 32, "Encryption key must be 32 bytes long");

    let mut iv = [0u8; IV_LENGTH];
    rand::rng().fill(&mut iv);

    let cipher = Encryptor::<Aes256>::new_from_slices(&key_bytes, &iv)
        .expect("Failed to create AES-256-CBC encryptor");

    let mut buffer = private_key.as_bytes().to_vec();
    let pos = buffer.len();
    buffer.resize(pos + Aes256::block_size(), 0);

    let encrypted_bytes = cipher.encrypt_padded_mut::<Pkcs7>(&mut buffer, pos).expect("Encryption failed");

    format!("{}:{}", hex::encode(iv), hex::encode(encrypted_bytes))
}