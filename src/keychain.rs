use ssh_agent::SSHAgentHandler;
use thrussh_keys::{
    key::{PublicKey, SignatureHash},
    parse_public_key_base64, PublicKeyBase64,
};
use tss_esapi::{
    abstraction::transient::{KeyMaterial, KeyParams, TransientKeyContextBuilder},
    interface_types::{
        algorithm::HashingAlgorithm, algorithm::RsaSchemeAlgorithm, key_bits::RsaKeyBits,
    },
    structures::{Digest, RsaExponent, RsaScheme, Signature},
    TransientKeyContext,
};

use std::{fs, io::Write};

use crate::handler::Handler;

pub struct PubKey {
    /// Name and purpose of the key
    pub label: String,
    /// Public and private key to load into the TPM for crytographic operations
    pub key: KeyMaterial,
    /// SSH formatted base-64 public key
    pub ssh: PublicKey,
    // TODO: store host restriction information as well
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
pub struct PubKeyStored {
    /// Name and purpose of the key
    pub label: String,
    /// Public and private key to load into the TPM for crytographic operations
    pub key: KeyMaterial,
    /// SSH formatted base-64 public key
    pub ssh: String, // pub ssh: String,
                     // TODO: store host restriction information as well
}

pub struct Keychain;

fn default_rsa_params() -> KeyParams {
    KeyParams::Rsa {
        size: RsaKeyBits::Rsa2048,
        // RSA SSA must be used here as it's part of pkcs1 v1.5
        scheme: RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
            .unwrap(),
        // the RSA Exponent 0 is shorthand for the TPM's max supported value, 2^16 + 1
        pub_exponent: RsaExponent::create(65537).unwrap(),
    }
}

impl Keychain {
    /// Retrieve keys from configured storage file
    pub fn get_public_keys() -> Vec<PubKey> {
        // create home dotfiles dir if it doesn't already exist
        let configdir = home::home_dir()
            .expect("Couldn't find home directory")
            .join(".tpmkey");

        if !configdir.exists() {
            fs::create_dir(&configdir).expect("Could not create configuration folder");
        }

        let keystore = if !configdir.join("keys.json").exists() {
            let mut handle = fs::File::create(configdir.join("keys.json"))
                .expect("Could not create configuration file");

            let keystore: Vec<PubKeyStored> = vec![];

            handle
                .write_fmt(format_args!(
                    "{}",
                    serde_json::to_string(&keystore).unwrap()
                ))
                .unwrap();

            keystore
        } else {
            let keystore: Vec<PubKeyStored> = serde_json::from_str(
                fs::read_to_string(configdir.join("keys.json"))
                    .expect("Could not access configuration file")
                    .as_str(),
            )
            .expect("Could not deserialize keys.json");

            keystore
        };

        keystore
            .into_iter()
            .map(|key| PubKey {
                label: key.label,
                key: key.key,
                ssh: parse_public_key_base64(&key.ssh).expect("Failed to interpret key"),
            })
            .collect()
    }

    pub fn get_public_key_by_fingerprint(key_id: &str) -> PublicKey {
        let keystore = Self::get_public_keys();

        let retrieved = keystore
            .into_iter()
            .find(|e| e.ssh.fingerprint() == key_id)
            .expect(
                format!(
                    "Could not locate key with fingerprint {} in keystore",
                    key_id,
                )
                .as_str(),
            );

        retrieved.ssh
    }

    pub fn get_public_key_by_name(key_name: &str) -> PublicKey {
        let keystore = Self::get_public_keys();

        let retrieved = keystore
            .into_iter()
            .find(|e| e.label == key_name)
            .expect(format!("Could not locate key with name {} in keystore", key_name,).as_str());

        retrieved.ssh
    }

    /// Retrieve a keypair by the hash of a pubkey
    pub fn get_public_key(key: &PublicKey) -> Result<PubKey, &'static str> {
        let keystore = Self::get_public_keys();

        let retrieved = keystore.into_iter().find(|e| e.ssh == *key).unwrap();

        Ok(retrieved)
    }

    fn get_context() -> TransientKeyContext {
        let esapi_context = TransientKeyContextBuilder::new()
            .with_tcti(
                tss_esapi::tcti_ldr::TctiNameConf::from_environment_variable()
                    .expect("Could not instantiate tcti from environment"),
            )
            .build()
            .expect("Could not instantiate tcti");

        esapi_context
    }

    /// Sign data with a keypair
    pub fn sign_data(data: &[u8], key: &PublicKey) -> Result<Vec<u8>, &'static str> {
        let mut esapi_context = Self::get_context();

        let keypair = Self::get_public_key(key).expect("Could not retrieve key for signing");

        use std::convert::TryFrom;

        let digest: Vec<u8> = match key {
            PublicKey::Ed25519(_) => unimplemented!(),
            PublicKey::RSA { hash, .. } => match hash {
                SignatureHash::SHA2_256 => {
                    use sha2::{Digest, Sha256};

                    let mut hash = Sha256::new();

                    hash.update(&data);

                    let digest: [u8; 32] = hash.finalize().into();
                    digest.to_vec()
                }
                SignatureHash::SHA2_512 => {
                    use sha2::{Digest, Sha512};

                    let mut hash = Sha512::new();

                    hash.update(&data);

                    let digest: [u8; 64] = hash.finalize().into();
                    digest.to_vec()
                }
                SignatureHash::SHA1 => unimplemented!("SHA1 is obsolete and is not supported."),
            },
        };

        let signature = esapi_context
            .sign(
                keypair.key.clone(),
                default_rsa_params(),
                None,
                Digest::try_from(digest.clone()).unwrap(),
            )
            .expect("Could not sign data");

        // ensure that signature is valid according to the TPM's internal representation
        debug_assert!({
            esapi_context
                .verify_signature(
                    keypair.key.clone(),
                    default_rsa_params(),
                    Digest::try_from(digest.clone()).unwrap(),
                    signature.clone(),
                )
                .expect("unable to verify signed data");
            true
        });

        // ensure that the signature is valid according to ssh's representation of the pubkey and signature
        debug_assert!({
            use signature::Verifier;
            use thrussh_keys::PublicKeyBase64;

            let ssh_formatted_key =
                ssh_key::public::PublicKey::from_bytes(&key.public_key_bytes()).unwrap();

            assert_eq!(
                &ssh_formatted_key.to_bytes().unwrap(),
                &key.public_key_bytes()
            );

            match &signature {
                Signature::RsaSsa(rsa_signature) => {
                    ssh_formatted_key
                        .verify(
                            &data,
                            &ssh_key::Signature::new(
                                ssh_key::Algorithm::Rsa {
                                    hash: Some(ssh_key::HashAlg::Sha256),
                                },
                                rsa_signature.signature().value().to_vec(),
                            )
                            .unwrap(),
                        )
                        .unwrap();
                }
                _ => unimplemented!(),
            };

            true
        });

        match signature {
            Signature::RsaSsa(rsa_signature) => Ok(rsa_signature.signature().value().to_vec()),
            _ => unimplemented!(),
        }
    }

    /// Delete a keypair
    pub fn delete_keypair(key: PublicKey) -> Result<(), &'static str> {
        let keystore = Self::get_public_keys();

        let keystore: Vec<PubKey> = keystore
            .into_iter()
            .filter(|oldkey| oldkey.ssh != key)
            .collect();

        Self::set_keystore(keystore);

        Ok(())
    }

    /// Set the contents of the keystore to a given value
    /// This will overwrite previous values of the keystore, but this is fine because storing data is hard.
    fn set_keystore(keyring: Vec<PubKey>) {
        // create home dotfiles dir if it doesn't already exist
        let configdir = home::home_dir()
            .expect("Couldn't find home directory")
            .join(".tpmkey");

        if !configdir.exists() {
            fs::create_dir(&configdir).expect("Could not create configuration folder");
        }

        let configpath = configdir.join("keys.json");
        let mut config_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&configpath)
            .unwrap();

        let keyring: Vec<PubKeyStored> = keyring
            .into_iter()
            .map(|key| PubKeyStored {
                label: key.label,
                key: key.key,
                ssh: key.ssh.public_key_base64(),
            })
            .collect();

        config_file
            .write_fmt(format_args!("{}", serde_json::to_string(&keyring).unwrap()))
            .unwrap();

        assert!(configpath.exists());
    }

    /// Generate a new keypair of type Algorithm. Currently, RSA1024 will be generated.
    /// TODO: support other algorithms.
    /// We can even add some extra assurance to unsupported algorithms like ed25519 by encrypting private key (using a rsa encryption key and tss_esapi rsa_encrypt)
    /// material and only decrypting it while we're about to use it. it's not ideal and has a larger attack surface
    /// than just TPM keys, but it adds some additional assurance.
    /// TODO: add assurance that only one key with a name can exist at a time. no duplicate names.
    pub fn generate_keypair(label: String) -> Result<(), &'static str> {
        let mut esapi_context = Self::get_context();

        let is_rsa = true;

        let (key, _) = esapi_context.create_key(default_rsa_params(), 0).unwrap();

        let new_pubkey = PubKey {
            ssh: if is_rsa {
                use openssl::pkey::PKey;
                use openssl::{bn::BigNum, pkey::Public, rsa::Rsa};
                use thrussh_keys::key::OpenSSLPKey;

                let rsa_n_param = match key.public() {
                    tss_esapi::utils::PublicKey::Rsa(val) => val.to_vec(),
                    _ => unimplemented!(),
                };

                let rsa_pub = OpenSSLPKey(
                    PKey::from_rsa(
                        Rsa::<Public>::from_public_components(
                            BigNum::from_slice(&rsa_n_param).unwrap(),
                            BigNum::from_u32(65537).unwrap(),
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                );

                let rsa_pub = PublicKey::RSA {
                    key: rsa_pub,
                    hash: thrussh_keys::key::SignatureHash::SHA2_256,
                };

                rsa_pub
            } else {
                unimplemented!()
            },
            label,
            key: key.clone(),
        };

        let thekey = new_pubkey.ssh.fingerprint();

        let mut keystore = Self::get_public_keys();
        keystore.push(new_pubkey);
        Self::set_keystore(keystore);

        let thekey = Self::get_public_key_by_fingerprint(thekey.as_str());
        let data_to_sign = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 16, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        ];

        let mut handler = Handler::new();
        handler.sign_request(thekey.public_key_bytes(), data_to_sign, 0);

        Ok(())
    }
}
