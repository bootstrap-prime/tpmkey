use byteorder::{BigEndian, ReadBytesExt};
use eagre_asn1::der::DER;
use openssl::pkey::PKey;
use std::io::{BufRead, Cursor, Read};
use thrussh_keys::{
    key::{OpenSSLPKey, PublicKey},
    PublicKeyBase64,
};

#[derive(Debug)]
pub struct ECDSASign {
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

der_sequence! {
    ECDSASign:
        r: NOTAG TYPE Vec<u8>,
        s: NOTAG TYPE Vec<u8>,
}

// pub static CURVE_INDETIFIER: &'static str = "nistp256";
// pub static CURVE_TYPE: &'static str = "ecdsa-sha2-nistp256";

pub static CURVE_IDENTIFIER: &'static str = "rsa";
pub static CURVE_TYPE: &'static str = "rsa-sha2-256";

pub struct EcdsaSha2Nistp256;
impl EcdsaSha2Nistp256 {
    // write to SSH-Key Format
    pub fn write(key: Vec<u8>) -> Vec<u8> {
        let is_rsa = true;

        if is_rsa {
            use openssl::{bn::BigNum, pkey::Public, rsa::Rsa};

            let rsa_pub = OpenSSLPKey(
                PKey::from_rsa(
                    Rsa::<Public>::from_public_components(
                        BigNum::from_slice(&key).unwrap(),
                        BigNum::from_u32(2_u32.pow(16) + 1).unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap(),
            );

            let pubkey = PublicKey::RSA {
                key: rsa_pub,
                hash: thrussh_keys::key::SignatureHash::SHA2_256,
            };

            pubkey.public_key_bytes()
        } else {
            unimplemented!()
        }
    }

    //read from SSH-key Format
    pub fn read(data: Vec<u8>) -> Vec<u8> {
        let mut cursor = Cursor::new(data);
        let len = cursor.read_u32::<BigEndian>().unwrap();
        //cursor.read(len);
        cursor.consume(len as usize);
        let len = cursor.read_u32::<BigEndian>().unwrap();
        cursor.consume(len as usize);
        let len = cursor.read_u32::<BigEndian>().unwrap();
        let mut buffer = vec![0; len as usize];
        cursor.read(&mut buffer).unwrap();
        buffer
    }

    pub fn parse_asn1(signed_data: Vec<u8>) -> ECDSASign {
        ECDSASign::der_from_bytes(signed_data).unwrap()
    }
}
