use tss_esapi::{
    abstraction::transient::{KeyMaterial, KeyParams, TransientKeyContextBuilder},
    interface_types::{
        algorithm::HashingAlgorithm, algorithm::RsaSchemeAlgorithm, key_bits::RsaKeyBits,
    },
    structures::{Digest, RsaExponent, RsaScheme, Signature},
    TransientKeyContext,
};

use std::{fs, io::Write};

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
pub struct PubKey {
    pub label: String,
    pub key: KeyMaterial,
    pub hash: Vec<u8>,
    // TODO: store host restriction information as well
}

pub struct Keychain;

fn default_rsa_params() -> KeyParams {
    KeyParams::Rsa {
        size: RsaKeyBits::Rsa1024,
        // RSA PSS <https://en.wikipedia.org/wiki/Probabilistic_signature_scheme> is a component of pkcs11 and I'm making the leap that it's the default to use here.
        scheme: RsaScheme::create(RsaSchemeAlgorithm::RsaPss, Some(HashingAlgorithm::Sha256))
            .unwrap(),
        pub_exponent: RsaExponent::create(0).unwrap(),
    }
}
impl Keychain {
    /// Retrieve keys from configured storage file
    pub fn get_public_keys() -> Vec<PubKey> {
        Self::get_keystore()
    }

    /// Retrieve a keypair by the hash of a pubkey
    pub fn get_public_key(hash: Vec<u8>) -> Result<PubKey, &'static str> {
        Ok(Self::get_public_keys()
            .iter()
            .find(|e| e.hash == hash)
            .unwrap()
            .clone())
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
    pub fn sign_data(data: Vec<u8>, key_hash: Vec<u8>) -> Result<Vec<u8>, &'static str> {
        let mut esapi_context = Self::get_context();

        let keypair = Self::get_public_key(key_hash).expect("Could not retrieve key for signing");

        use std::convert::TryFrom;

        let signature = esapi_context
            .sign(
                keypair.key,
                default_rsa_params(),
                None,
                Digest::try_from(data).unwrap(),
            )
            .expect("Could not sign data");

        match signature {
            Signature::RsaPss(rsa_signature) | Signature::RsaSsa(rsa_signature) => {
                Ok(rsa_signature.signature().value().to_vec())
            }
            _ => unimplemented!(),
        }
    }

    /// Delete a keypair
    pub fn delete_keypair(hash: Vec<u8>) -> Result<(), &'static str> {
        let keystore = Self::get_keystore();

        let keystore: Vec<PubKey> = keystore
            .into_iter()
            .filter(|key| key.hash != hash)
            .collect();

        Self::set_keystore(keystore);

        Ok(())
    }

    fn get_keystore() -> Vec<PubKey> {
        // create home dotfiles dir if it doesn't already exist
        let configdir = home::home_dir()
            .expect("Couldn't find home directory")
            .join(".tpmkey");

        if !configdir.exists() {
            fs::create_dir(&configdir).expect("Could not create configuration folder");
        }

        if !configdir.join("keys.json").exists() {
            let mut handle = fs::File::create(configdir.join("keys.json"))
                .expect("Could not create configuration file");

            let keystore: Vec<PubKey> = vec![];

            handle
                .write_fmt(format_args!(
                    "{}",
                    serde_json::to_string(&keystore).unwrap()
                ))
                .unwrap();

            keystore
        } else {
            let keystore: Vec<PubKey> = serde_json::from_str(
                fs::read_to_string(configdir.join("keys.json"))
                    .expect("Could not access configuration file")
                    .as_str(),
            )
            .expect("Could not deserialize keys.json");

            keystore
        }
    }

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

        config_file
            .write_fmt(format_args!("{}", serde_json::to_string(&keyring).unwrap()))
            .unwrap();

        assert!(configpath.exists());
    }

    /// Generate a new keypair of type Algorithm. Currently, RSA1024 will be generated.
    /// TODO: support other algorithms.
    pub fn generate_keypair(label: String) -> Result<(), &'static str> {
        let mut esapi_context = Self::get_context();

        let (key, _) = esapi_context.create_key(default_rsa_params(), 0).unwrap();

        let new_pubkey = PubKey {
            hash: {
                use sha2::{Digest, Sha256};

                let mut hash = Sha256::new();
                match key.public() {
                    tss_esapi::utils::PublicKey::Rsa(val) => {
                        hash.update(val);
                    }
                    _ => unimplemented!(),
                }

                hash.finalize().to_vec()
            },
            label,
            key: key.clone(),
        };

        let mut keystore = Self::get_keystore();

        keystore.push(new_pubkey);

        Self::set_keystore(keystore);

        Ok(())
    }
}
