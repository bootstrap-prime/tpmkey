use ssh_agent::Identity;
use ssh_agent::Response;
use ssh_agent::SSHAgentHandler;

use thrussh_keys::key::PublicKey;

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
                let b64sig = thrussh_keys::signature::Signature::RSA {
                    hash: *hash,
                    bytes: raw_signature.clone(),
                }
                .to_base64();

                base64::decode(b64sig).unwrap()
            }
        };

        Ok(Response::SignResponse {
            algo_name: String::from(pubkey.name()),
            signature: signature,
        })
    }
}
