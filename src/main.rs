use argon2_kdf::{Algorithm, Hasher, Secret};
use base64::engine::general_purpose::STANDARD as b64;
use base64::Engine;
use zeroize::Zeroizing;

use std::io;
use std::io::Write;

fn main() {
    let password = get_input("Enter the password you would like to hash: ", true, |i| {
        if i.is_empty() {
            Err("Password cannot be empty!")
        } else {
            let password_is_b64_encoded = get_input(
                "Was the password base64 encoded? (y|n) [default: n] ",
                false,
                |i| match i.to_lowercase().as_str() {
                    "n" | "no" | "" => Ok(false),
                    "y" | "yes" => Ok(true),
                    _ => Err("Please enter \"y\" or \"n\""),
                },
            );

            if password_is_b64_encoded {
                match b64.decode(i) {
                    Ok(p) => Ok(Zeroizing::new(p)),
                    Err(_) => Err("Password is not valid base64!"),
                }
            } else {
                Ok(Zeroizing::new(i.as_bytes().to_vec()))
            }
        }
    });

    let algorithm = get_input(
        "Which algorithm should be used? (argon2id|argon2i|argon2d) [default: argon2id] ",
        false,
        |i| match i.to_lowercase().as_str() {
            "argon2id" | "" => Ok(Algorithm::Argon2id),
            "argon2i" => Ok(Algorithm::Argon2i),
            "argon2d" => Ok(Algorithm::Argon2d),
            _ => Err("Invalid algorithm option"),
        },
    );

    let salt_len = get_input(
        "How long should the salt be (in bytes)? (positive integer) [default: 16] ",
        false,
        |i| {
            if i.is_empty() {
                Ok(16u32)
            } else {
                match i.parse() {
                    Ok(len) => Ok(len),
                    Err(_) => Err("Invalid salt length"),
                }
            }
        },
    );

    let hash_len = get_input(
        "How long should the hash be (in bytes)? (positive integer) [default: 32] ",
        false,
        |i| {
            if i.is_empty() {
                Ok(32u32)
            } else {
                match i.parse() {
                    Ok(len) => Ok(len),
                    Err(_) => Err("Invalid hash length"),
                }
            }
        },
    );

    let iters = get_input(
        "How many iterations should be required for hashing? (positive integer) [default: 18] ",
        false,
        |i| {
            if i.is_empty() {
                Ok(18u32)
            } else {
                match i.parse() {
                    Ok(iters) => Ok(iters),
                    Err(_) => Err("Invalid iteration count"),
                }
            }
        },
    );

    let memory_cost_kib = get_input("How much memory should be required for hashing (in KiB)? (positive integer) [default: 62500] ", false, |i| {
        if i.is_empty() {
            Ok(62500u32)
        } else {
            match i.parse() {
                Ok(mem_cost) => Ok(mem_cost),
                Err(_) => Err("Invalid memory cost"),
            }
        }
    });

    let thread_count = get_input(
        "How many threads should be required for hashing? (positive integer) [default: 1] ",
        false,
        |i| {
            if i.is_empty() {
                Ok(1u32)
            } else {
                match i.parse() {
                    Ok(threads) => Ok(threads),
                    Err(_) => Err("Invalid thread count"),
                }
            }
        },
    );

    let secret = get_input(
        "Enter a base64-encoded secret to be used for hashing (leave blank for no secret): ",
        true,
        |i| {
            if i.trim().is_empty() {
                Ok(None)
            } else {
                match b64.decode(i) {
                    Ok(s) => Ok(Some(Zeroizing::new(s))),
                    Err(_) => Err("Secret is not valid base64!"),
                }
            }
        },
    );

    println!();
    println!("Hashing...");

    let mut hasher = Hasher::new()
        .algorithm(algorithm)
        .salt_length(salt_len)
        .hash_length(hash_len)
        .iterations(iters)
        .memory_cost_kib(memory_cost_kib)
        .threads(thread_count);

    let hash = if let Some(secret) = secret {
        hasher = hasher.secret(Secret::from(&secret[..]));
        hasher.hash(&password).expect("Argon2 hashing failed")
    } else {
        hasher.hash(&password).expect("Argon2 hashing failed")
    };

    println!("Hash: {}", hash.to_string());
}

fn get_input<T>(
    prompt: &str,
    is_sensitive: bool,
    convert: impl Fn(&str) -> Result<T, &'static str>,
) -> T {
    let converted_input: T;

    loop {
        print!("{prompt}");
        io::stdout().flush().expect("Failed to flush stdout");

        let mut input = if is_sensitive {
            Zeroizing::new(rpassword::read_password().expect("Failed to read from stdin"))
        } else {
            let mut buf = String::new();

            io::stdin()
                .read_line(&mut buf)
                .expect("Failed to read from stdin");

            Zeroizing::new(buf)
        };

        // Remove extra linebreak
        if input.ends_with('\n') {
            input.pop();
        }

        if input.ends_with('\r') {
            input.pop();
        }

        match convert(&input) {
            Ok(i) => {
                converted_input = i;
                break;
            }
            Err(err_msg) => {
                println!("{err_msg}");
                continue;
            }
        };
    }

    converted_input
}
