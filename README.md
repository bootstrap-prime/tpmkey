# TPMKey

[![MIT Licensed][license-image]][license-link]

## About
TPMKey is an SSH Agent that allow users to authenticate to SSH servers using a TPM2.0 on linux systems.

## How it Works?
The TPM is a hardware-based key manager that’s isolated from the main processor to provide an extra layer of security. When you store a private key in the TPM, you never actually handle the key, making it difficult for the key to become compromised. Instead, you instruct the TPM to create the key, securely store it, and perform operations with it. You receive only the output of these operations, such as encrypted data or a cryptographic signature verification outcome.

### Limitations
* Only supports linux with a TPM module. 

## Install

**Nixos**

**Manual Installation**

## Usage

For the help menu:

```sh
user@linux $ tpmkey -h
TPMKey 1.0
Nicolas Trippar <ntrippar@gmail.com>
Use Secure Enclave for SSH Authentication

USAGE:
    tpmkey [FLAGS] [OPTIONS]

FLAGS:
        --daemon       Run the daemon
    -h, --help         Prints help information
        --list-keys    List all keys
    -V, --version      Prints version information

OPTIONS:
        --delete-keypair <ID>         Deletes the keypair
        --export-key <ID>             export key to OpenSSH Format
        --generate-keypair <LABEL>    Generate a key inside the Secure Enclave
```


**Examples**

Create KeyPair inside the TPM:

```sh
ntrippar@macbookpro:~% tpmkey --generate-keypair "Github Key"
Keypair Github Key successfully generated

```

List keys in the TPM:

```sh
ntrippar@macbookpro:~% tpmkey --list-keys

┌────────────────────┬──────────────────────────────────────────────────┐
│       Label        │                        ID                        │
├────────────────────┼──────────────────────────────────────────────────┤
│     Github Key     │     d179eb4c2d6a242de64e82240b8b6e611cf0d729     │
└────────────────────┴──────────────────────────────────────────────────┘
```

Export public key to OpenSSH format:

```sh
ntrippar@macbookpro:~% tpmkey --export-key d179eb4c2d6a242de64e82240b8b6e611cf0d729
ecdsa-sha2-nistp25 AAAAEmVjZHNhLXNoYTItbmlzdHAyNQAAAAhuaXN0cDI1NgAAAEEE8HM7SBdu3yOYkmF0Wnj/q8t2NJC6JYJWZ4IyvkOVIeUs6mi4B424bAjhZ4Awgk5ax9r25RB3Q8tL2/7J/3xchQ==
```

Delete Keypair:

```sh
ntrippar@macbookpro:~% tpmkey --delete-keypair d179eb4c2d6a242de64e82240b8b6e611cf0d729
Key d179eb4c2d6a242de64e82240b8b6e611cf0d729 successfully deleted
```

Use key for a specific host:

1. export the public key from tpmkey and save it to a file
```sh
ntrippar@macbookpro:~% tpmkey --export-key d179eb4c2d6a242de64e82240b8b6e611cf0d729 > ~/.ssh/example.com.pub
```
2. on the ssh config file located in `~/.ssh/config` we should add a entry so the ssh only query that key for the given host

```
Host example.com
    IdentityFile ~/.ssh/example.com.pub
    IdentitiesOnly yes
```

## How to Build

**Build**

Tpmkey is built with [Cargo](https://crates.io/), the Rust package manager.

```sh
git clone https://github.com/ntrippar/tpmkey
cd tpmkey
cargo build --release
```

## Contribute
Members of the open-source community are encouraged to submit pull requests directly through GitHub.
