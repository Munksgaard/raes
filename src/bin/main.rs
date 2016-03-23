extern crate raes;

extern crate getopts;

use std::env;
use std::io::{stdout, Read, stdin, Write};
use std::fs::File;
use std::ascii::AsciiExt;
use getopts::Options;
use raes::{Cipher, Mode};
use std::path::Path;

static NAME: &'static str = "raes";
static VERSION: &'static str = "0.0.1";

#[derive(Eq, PartialEq)]
enum Operation {
    Help,
    Encrypt,
    Decrypt,
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut opts = Options::new();
    opts.optflag("e", "encrypt", "encrypt plaintext");
    opts.optflag("d", "decrypt", "decrypt ciphertext");
    opts.optflag("h", "help", "print help");
    opts.optopt("k", "key", "key to use", "KEY");
    opts.optopt("m", "mode", "mode to use (default ECB)", "MODE");
    opts.optopt("", "iv", "initialization vector", "IV");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m },
        Err(f) => { panic!(f.to_string()) }
    };

    let version = format!("{} {}", NAME, VERSION);
    let program = &args[0];
    let arguments = "[SOURCE]... [DEST]...";
    let brief = "Encrypt or decrypt a file using AES-128. Only ECB mode is supported at the moment.";
    let help = format!("{}\n\nUsage:\n  {} {}\n\n{}",
                       version, program, arguments, opts.usage(brief));
    let operation =
        if matches.opt_present("decrypt") {
            Operation::Decrypt
        } else if matches.opt_present("encrypt") {
            Operation::Encrypt
        } else {
            Operation::Help
        };

    let key = matches.opt_str("key");

    let mut stdin_buf;
    let mut file_buf;
    let input =
        if matches.free.is_empty() || &matches.free[0] == "-" {
            stdin_buf = stdin();
            &mut stdin_buf as &mut Read
        } else {
            let path = Path::new(&matches.free[0]);
            file_buf = File::open(&path).unwrap();
            &mut file_buf as &mut Read
        };

    let cipher = raes::Cipher::AES;
    let mode = match &matches.opt_str("mode").unwrap_or("ECB".to_string()).to_ascii_uppercase()[..] {
        "ECB" => raes::Mode::ECB,
        "CBC" => raes::Mode::CBC,
        _ => panic!("Unsupported mode"),
    };

    let iv = matches.opt_str("iv").map(|s| s.into_bytes());

    match operation {
        Operation::Decrypt => decrypt(cipher, mode, input, key, iv),
        Operation::Encrypt => encrypt(cipher, mode, input, key, iv),
        Operation::Help => println!("{}", help),
    }
}

fn encrypt<R: Read+?Sized>(cipher: Cipher, mode: Mode, input: &mut R, key: Option<String>, iv: Option<Vec<u8>>) {
    let k = match key {
        Some(k) => k,
        _ => panic!("Need key")
    };

    let mut buf = Vec::new();
    match input.read_to_end(&mut buf) {
        Ok(_) => {},
        Err(err) => panic!("Read failed: {}", err)
    }

    let mut out = stdout();
    let bytes = raes::encrypt(cipher, mode, &buf[..], k.as_bytes(), iv);
    out.write(&bytes[..]).unwrap();
}

fn decrypt<R: Read+?Sized>(cipher: Cipher, mode: Mode, input: &mut R, key: Option<String>, iv: Option<Vec<u8>>) {
    let k = match key {
        Some(k) => k,
        _ => panic!("Need key")
    };

    let mut buf = Vec::new();
    match input.read_to_end(&mut buf) {
        Ok(_) => {},
        Err(err) => panic!("Read failed: {}", err)
    }

    let mut out = stdout();
    let bytes = raes::decrypt(cipher, mode, &buf[..], k.as_bytes(), iv);
    out.write(&bytes[..]).unwrap();
}
