use clap::Parser;
use md5::{Digest, Md5};
use sha2::Sha256;
use std::fs::File;
use std::io::{self, Read};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    fpath: String,
}

fn open_file(path: &String) -> Result<File, std::io::Error> {
    let file: File = File::open(path)?; // Try to open the file
    Ok(file) // If successful, return the file
}

fn generate_md5(file: &mut File) -> io::Result<String> {
    let mut hasher = Md5::new();
    let mut buffer = [0u8; 1024];

    while let Ok(byte_read) = file.read(&mut buffer) {
        if byte_read == 0 {
            break;
        }
        hasher.update(&buffer[..byte_read]);
    }

    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

fn generate_sha256(file: &mut File) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024];

    while let Ok(byte_read) = file.read(&mut buffer) {
        if byte_read == 0 {
            break;
        }
        hasher.update(&buffer[..byte_read]);
    }

    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

fn main() {
    let args = Args::parse();
    println!("File Name: {}", args.fpath);
    let mut file = match open_file(&args.fpath) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to open file: {}", e);
            return;
        }
    };

    let md5 = generate_md5(&mut file);
    match md5 {
        Ok(hash) => println!("MD5 Hash is: {}", hash),
        Err(e) => eprintln!("Failed to generate MD5: {}", e),
    }

    let sha256 = generate_sha256(&mut file);
    match sha256 {
        Ok(hash) => println!("Sha256 Hash is: {}", hash),
        Err(e) => eprintln!("Failed to generate SHA256: {}", e),
    }
}
