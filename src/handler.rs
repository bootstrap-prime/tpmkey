use ssh_agent::Identity;
use ssh_agent::Response;
use ssh_agent::SSHAgentHandler;

use ecdsa::{EcdsaSha2Nistp256, CURVE_TYPE};

use byteorder::{BigEndian, WriteBytesExt};
use std::io::Write;

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
        let signed = Keychain::sign_data(data, &pubkey)?;

        let is_rsa = true;

        if is_rsa {
            //sign that we would return
            let mut signature: Vec<u8> = Vec::new();

            signature.write_u32::<BigEndian>(signed.len() as u32)?;
            signature.write_all(signed.as_slice())?;

            Ok(Response::SignResponse {
                algo_name: String::from(pubkey.name()),
                signature,
            })
        } else {
            unimplemented!()
            // let ecdsasign = EcdsaSha2Nistp256::parse_asn1(signed);

            // //write signR
            // signature
            //     .write_u32::<BigEndian>(ecdsasign.r.len() as u32)
            //     .unwrap();
            // signature.write_all(ecdsasign.r.as_slice())?;

            // //write signS
            // signature
            //     .write_u32::<BigEndian>(ecdsasign.s.len() as u32)
            //     .unwrap();
            // signature.write_all(ecdsasign.s.as_slice())?;

            // response signature
        }
    }
}
