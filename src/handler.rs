use signature::Verifier;
use ssh_agent::Identity;
use ssh_agent::Response;
use ssh_agent::SSHAgentHandler;

use ecdsa::{EcdsaSha2Nistp256, CURVE_TYPE};

use byteorder::{BigEndian, WriteBytesExt};
use std::io::Write;
use thrussh_keys::encoding::Encoding;
use thrussh_keys::key::KeyPair;
use thrussh_keys::key::PublicKey;
use thrussh_keys::PublicKeyBase64;

// use ecdsa::{EcdsaSha2Nistp256, CURVE_TYPE};
use Keychain;

use ssh_agent::error::HandleResult;

pub struct Handler;
impl SSHAgentHandler for Handler {
    fn new() -> Self {
        Self {}
    }

    fn identities(&mut self) -> HandleResult<Response> {
        // list identities and return
        let keys = Keychain::get_public_keys();
        let mut idents = Vec::new();
        for key in keys {
            idents.push(Identity {
                key_blob: thrussh_keys::PublicKeyBase64::public_key_bytes(&key.ssh),
                key_comment: String::from(key.ssh.name()),
            });
        }
        Ok(Response::Identities(idents))
    }

    fn sign_request(
        &mut self,
        pubkey: Vec<u8>,
        data: Vec<u8>,
        _flags: u32,
    ) -> HandleResult<Response> {
        // parse the pubkey that server send to us, then hash it and we will use that
        // hash to get the key from the enclave to sign
        let pubkey =
            thrussh_keys::key::parse_public_key(&pubkey).expect("Passed invalid public key by ssh");

        // here we sign the request and do all the enclave communication
        let raw_signature = Keychain::sign_data(&data, &pubkey)?;

        let signature = match pubkey {
            PublicKey::Ed25519(_) => unimplemented!(),
            PublicKey::RSA { ref hash, ref key } => {
                // https://tools.ietf.org/html/draft-rsa-dsa-sha2-256-02#section-2.2
                let mut buffer = cryptovec::CryptoVec::new();
                let name = hash.name();
                println!("{:?}", name);
                buffer.push_u32_be((name.0.len() + raw_signature.len() + 8) as u32);
                buffer.extend_ssh_string(name.0.as_bytes());
                buffer.extend_ssh_string(&raw_signature);

                let resultOne = buffer.to_vec();

                let b64sig = thrussh_keys::signature::Signature::RSA {
                    hash: *hash,
                    bytes: raw_signature.clone(),
                }
                .to_base64();

                println!("{}", b64sig);

                use signature::Verifier;
                use ssh_key::{public::RsaPublicKey, Algorithm, HashAlg, Signature};

                let resultTwo = base64::decode(b64sig).unwrap();

                assert_eq!(resultOne, resultTwo);

                resultOne
                // b64sig.as_bytes().to_vec()
            }
        };

        debug_assert!({
            ssh_key::public::PublicKey::from_bytes(&pubkey.public_key_bytes())
                .unwrap()
                .verify(
                    &data,
                    &ssh_key::Signature::new(
                        ssh_key::Algorithm::Rsa {
                            hash: Some(ssh_key::HashAlg::Sha256),
                        },
                        signature.clone(),
                    )
                    .unwrap(),
                )
                .unwrap();

            true
        });

        Ok(Response::SignResponse {
            algo_name: String::from(pubkey.name()),
            signature,
        })

        // if is_rsa {
        //     //sign that we would return
        //     let mut buffer: Vec<u8> = Vec::new();

        //     // signature.write_u32::<BigEndian>(signed.len() as u32)?;
        //     // signature.write_all(signed.as_slice())?;

        //     debug_assert!({ pubkey.verify_detached(&data, &buffer) });

        //     Ok(Response::SignResponse {
        //         algo_name: String::from(pubkey.name()),
        //         signature: buffer,
        //     })
        // } else {
        //     unimplemented!()
        //     // let ecdsasign = EcdsaSha2Nistp256::parse_asn1(signed);

        //     // //write signR
        //     // signature
        //     //     .write_u32::<BigEndian>(ecdsasign.r.len() as u32)
        //     //     .unwrap();
        //     // signature.write_all(ecdsasign.r.as_slice())?;

        //     // //write signS
        //     // signature
        //     //     .write_u32::<BigEndian>(ecdsasign.s.len() as u32)
        //     //     .unwrap();
        //     // signature.write_all(ecdsasign.s.as_slice())?;

        //     // response signature
        // }
    }
}
