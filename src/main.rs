use clap::Parser;
use digest::DynDigest;
use std::fs::File;
use std::io::{self, Read, Seek};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    fpath: String,
}

fn open_file(path: &String) -> Result<File, std::io::Error> {
    let file: File = File::open(path)?;
    Ok(file) }

fn select_hasher(s: &str) -> Box<dyn DynDigest> {
    match s {
        "md5" => Box::new(md5::Md5::default()),
        "sha1" => Box::new(sha1::Sha1::default()),
        "sha224" => Box::new(sha2::Sha224::default()),
        "sha256" => Box::new(sha2::Sha256::default()),
        "sha384" => Box::new(sha2::Sha384::default()),
        "sha512" => Box::new(sha2::Sha512::default()),
        _ => unimplemented!("unsupported digest: {}", s),
    }
}

fn bytes_to_hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn generate_hash(file: &mut File, hash: &mut Box<dyn DynDigest>) -> io::Result<String> {
    let mut buffer = [0u8; 1024];
    file.seek(std::io::SeekFrom::Start(0))?;

    while let Ok(byte_read) = file.read(&mut buffer) {
        if byte_read == 0 {
            break;
        }
        hash.update(&buffer[..byte_read]);
    }

    let result = hash.finalize_reset();
    Ok(bytes_to_hex_string(&result))
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

    let mut md5: Box<dyn DynDigest> = select_hasher("md5");
    let md5_hash = generate_hash(&mut file, &mut md5).unwrap();
    println!("MD5: \t{:#?}", md5_hash);

    let mut sha1: Box<dyn DynDigest> = select_hasher("sha1");
    let sha1_hash = generate_hash(&mut file, &mut sha1).unwrap();
    println!("Sha1: \t{:#?}", sha1_hash);

    let mut sha256: Box<dyn DynDigest> = select_hasher("sha256");
    let sha256_hash = generate_hash(&mut file, &mut sha256).unwrap();
    println!("Sha256: {:#?}", sha256_hash);
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_FILE: &str = "./test/test.txt";

    fn create_test_args() -> Args {
        Args {
            fpath: TEST_FILE.to_string(),
        }
    }

    #[test]
    fn args_fpath_should_be_string() {
        let args = create_test_args();
        assert_eq!(args.fpath, TEST_FILE);
    }

    #[test]
    fn should_open_file() {
        let args = create_test_args();
        assert!(open_file(&args.fpath).is_ok());
    }

    #[test]
    fn should_not_find_non_existant_file() {
        let args = Args {
            fpath: String::from("./doesnotexist.txt"),
        };
        assert!(open_file(&args.fpath).is_err());
    }

    #[test]
    fn should_generate_md5() {
        // md5 d8e8fca2dc0f896fd7cb4cb0031ba249  test/test.txt
        let args = create_test_args();
        let mut algo: Box<dyn DynDigest> = select_hasher("md5");
        let mut file = open_file(&args.fpath).unwrap();
        assert_eq!(
            generate_hash(&mut file, &mut algo).unwrap(),
            "d8e8fca2dc0f896fd7cb4cb0031ba249"
        );
    }

    #[test]
    fn should_generate_sha256() {
        // f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2  ./test/test.txt
        let args = create_test_args();
        let mut algo: Box<dyn DynDigest> = select_hasher("sha256");
        let mut file = open_file(&args.fpath).unwrap();
        assert_eq!(
            generate_hash(&mut file, &mut algo).unwrap(),
            "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"
        );
    }
}
