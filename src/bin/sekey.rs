extern crate clap;
extern crate env_logger;
extern crate sekey;
extern crate ssh_agent;
#[macro_use]
extern crate prettytable;
extern crate base64;
extern crate hex;

use clap::{App, Arg};
use std::os::unix::net::UnixListener;

use prettytable::format;
use prettytable::Table;

use sekey::handler::Handler;
use sekey::Keychain;
use ssh_agent::SSHAgentHandler;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

static TPMKEY_HOME_FOLDER: &'static str = "/.tpmkey/";
static SSH_AGENT_PIPE: &'static str = "ssh-agent.ssh";

fn create_home_path(home: PathBuf) -> Result<(), &'static str> {
    let home = format!("{}{}", home.display(), TPMKEY_HOME_FOLDER);
    let home = Path::new(home.as_str());
    if !Path::new(home).exists() {
        match fs::create_dir(home) {
            Ok(_) => Ok(()),
            Err(_) => Err("Error creating home folder"),
        }
    } else {
        Ok(())
    }
}

fn main() {
    env_logger::init().unwrap_or_else(|err| {
        eprintln!("logger init error {}", err);
    });

    let matches = App::new("SeKey")
        .version("1.0")
        .about("Use the Trusted Platform Module for SSH Authentication")
        .arg(
            Arg::with_name("generate-keypair")
                .long("generate-keypair")
                .short("c")
                .value_name("LABEL")
                .help("Generate a key inside the Trusted Platform Module")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("list-keys")
                .long("list-keys")
                .short("l")
                .help("List all keys")
                .takes_value(false)
                .conflicts_with_all(&["generate-keypair"]),
        )
        .arg(
            Arg::with_name("daemon")
                .long("daemon")
                .help("Run the daemon")
                .takes_value(false)
                .conflicts_with_all(&["list-keys"]),
        )
        .arg(
            Arg::with_name("export-key")
                .long("export-key")
                .short("e")
                .value_name("ID")
                .help("export key to OpenSSH Format")
                .takes_value(true)
                .conflicts_with_all(&["list-keys"]),
        )
        .arg(
            Arg::with_name("delete-keypair")
                .long("delete-keypair")
                .short("d")
                .value_name("ID")
                .help("Deletes the keypair")
                .takes_value(true)
                .conflicts_with_all(&["list-keys"]),
        )
        .get_matches();

    // printing format
    let format = format::FormatBuilder::new()
        .column_separator('│')
        .borders('│')
        .separators(
            &[format::LinePosition::Top],
            format::LineSeparator::new('─', '┬', '┌', '┐'),
        )
        .separators(
            &[format::LinePosition::Title],
            format::LineSeparator::new('─', '┼', '├', '┤'),
        )
        .separators(
            &[format::LinePosition::Bottom],
            format::LineSeparator::new('─', '┴', '└', '┘'),
        )
        .padding(5, 5)
        .build();

    // match list-keys
    if matches.is_present("list-keys") {
        let mut table = Table::new();
        table.set_format(format);
        table.set_titles(row![bc => "Label", "Fingerprint"]);

        let keys = Keychain::get_public_keys();
        if keys.len() >= 1 {
            for key in keys {
                //key.hash
                table.add_row(row![key.label, key.ssh.fingerprint()]);
            }
            table.printstd();
        } else {
            println!("No keys stored");
        }
    }

    // match export-key
    if let Some(key_id) = matches.value_of("export-key") {
        let key = Keychain::get_public_key_by_fingerprint(key_id);
        let keyblob = thrussh_keys::PublicKeyBase64::public_key_base64(&key);
        println!(
            "{} {}",
            key.name(),
            keyblob.split_whitespace().collect::<String>()
        )
    }

    if let Some(key_id) = matches.value_of("delete-keypair") {
        let key = Keychain::get_public_key_by_fingerprint(&key_id);
        Keychain::delete_keypair(key).unwrap();
        println!("Key SHA256:{} successfully deleted", key_id);
    }

    if let Some(label) = matches.value_of("generate-keypair") {
        let key = Keychain::generate_keypair(label.to_string());
        match key {
            Ok(_) => {
                println!("Keypair SHA256:{} successfully generated", label)
            }
            Err(_) => eprintln!("Error generating key"),
        }
    }

    //generate_keypair
    // run the daemon!
    if matches.is_present("daemon") {
        match home::home_dir() {
            Some(path) => match create_home_path(path.clone()) {
                Ok(_) => {
                    let pipe =
                        format!("{}{}{}", path.display(), TPMKEY_HOME_FOLDER, SSH_AGENT_PIPE);
                    let pipe = Path::new(pipe.as_str());
                    if fs::metadata(&pipe).is_ok() {
                        if let Ok(_) = fs::remove_file(&pipe) {
                            println!("Pipe deleted");
                        }
                    }
                    println!("binding to {}", pipe.display());
                    let listener = UnixListener::bind(pipe);
                    let handler = Handler::new();
                    ssh_agent::Agent::run(handler, listener.unwrap());
                }
                Err(_) => eprintln!("Error creating home path"),
            },
            None => eprintln!("Impossible to get home dir!"),
        }
    }
}
