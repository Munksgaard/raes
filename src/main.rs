#![allow(dead_code)]

extern crate raes;

extern crate getopts;

use std::os;
use std::io::{File, stdout};
use std::io::stdio::stdin_raw;
use getopts::{getopts, optflag, optopt, usage};


static NAME: &'static str = "raes";
static VERSION: &'static str = "0.0.1";

#[deriving(Eq, PartialEq)]
enum Mode {
    Help,
    Encode,
    Decode,
}

fn main() {
    let opts = [
        optflag("e", "encode", "encode plaintext"),
        optflag("d", "decode", "decode ciphertext"),
        optflag("h", "help", "print help"),
        optopt("k", "key", "key to use", "KEY")];

    let args: Vec<String> = os::args().iter().map(|x| x.to_string()).collect();

    getopts(args.tail(), opts).map_err(|e| format!("{}", e)).and_then(|m| {
        let version = format!("{} {}", NAME, VERSION);
        let program = args[0].as_slice();
        let arguments = "[SOURCE]... [DEST]...";
        let brief = "Encode or decode a file using AES-128. Only ECB mode is supported at the moment.";
        let help = format!("{}\n\nUsage:\n  {} {}\n\n{}",
                           version, program, arguments, usage(brief, opts),);
        let mode =
            if m.opt_present("decode") {
                Decode
            } else if m.opt_present("encode") {
                Encode
            } else {
                Help
            };

        let key = m.opt_str("key");

        let mut stdin_buf;
        let mut file_buf;
        let input =
            if m.free.is_empty() || m.free[0].as_slice() == "-" {
                stdin_buf = stdin_raw();
                &mut stdin_buf as &mut Reader
            } else {
                let path = Path::new(m.free[0].as_slice());
                file_buf = File::open(&path);
                &mut file_buf as &mut Reader
            };

        match mode {
            Decode => decode(input, key),
            Encode => encode(input, key),
            Help => println!("{}", help)};

        Ok(0u8)
    }).map_err(|message| warn(message.as_slice())).unwrap();
}

fn encode(input: &mut Reader, key: Option<String>) {
    let k = match key {
        Some(k) => k,
        _ => fail!("Need key")
    };

    let v = match input.read_to_end() {
        Ok(m) => m,
        Err(err) => fail!("Read failed: {}", err)
    };

    let mut out = stdout();
    let bytes = raes::encode_aes_ecb(v.as_slice(), k.as_bytes());
    out.write(bytes.as_slice()).unwrap();
}

fn decode(input: &mut Reader, key: Option<String>) {
    let k = match key {
        Some(k) => k,
        _ => fail!("Need key")
    };

    let v = match input.read_to_end() {
        Ok(m) => m,
        Err(err) => fail!("Read failed: {}", err)
    };

    let mut out = stdout();
    let bytes = raes::decode_aes_ecb(v.as_slice(), k.as_bytes());
    out.write(bytes.as_slice()).unwrap();
}

fn warn(message: &str) {
    fail!("{}: {}", os::args().get(0), message);
}
