mod keygen;
mod encrypt;
mod decrypt;
mod utils;
mod test;

use crate::keygen::keygen_string;
use crate::encrypt::encrypt_string;
use crate::decrypt::decrypt_string;
use crate::utils::Parameters;
use polynomial_ring::Polynomial;
use clap::{Parser, Subcommand};
use std::fs;

/// Module-LWE CLI
#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a keypair
    Keygen {
        /// Optional parameters n, q, k
        #[arg(long)]
        n: Option<usize>,
        #[arg(long)]
        q: Option<i64>,
        #[arg(long)]
        k: Option<usize>,

        /// Optional: save keys to files
        #[arg(long)]
        save_keys: bool,
    },

    /// Encrypt a message
    Encrypt {
        /// Public key (base64 string)
        #[arg(long, group = "pubkey_source")]
        pubkey: Option<String>,

        /// Public key file
        #[arg(long, group = "pubkey_source")]
        pubkey_file: Option<String>,

        /// Message to encrypt
        message: String,

        /// Optional parameters n, q, k
        #[arg(long)]
        n: Option<usize>,
        #[arg(long)]
        q: Option<i64>,
        #[arg(long)]
        k: Option<usize>,

        /// Optional: save ciphertext to file
        #[arg(long)]
        ciphertext_file: Option<String>,
    },

    /// Decrypt a message
    Decrypt {
        /// Secret key (base64 string)
        #[arg(long, group = "seckey_source")]
        secret: Option<String>,

        /// Secret key file
        #[arg(long, group = "seckey_source")]
        secret_file: Option<String>,

        /// Ciphertext to decrypt
        ciphertext: Option<String>,

        /// Ciphertext file
        #[arg(long, group = "ciphertext_source")]
        ciphertext_file: Option<String>,

        /// Optional parameters n, q, k
        #[arg(long)]
        n: Option<usize>,
        #[arg(long)]
        q: Option<i64>,
        #[arg(long)]
        k: Option<usize>,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Keygen { n, q, k, save_keys } => {
            let params = build_params(*n, *q, *k);
            let keypair = keygen_string(&params, None);

            if *save_keys {
                use std::fs::File;
                use std::io::Write;

                let public_key = keypair.get("public").expect("No public key found");
                let secret_key = keypair.get("secret").expect("No secret key found");

                File::create("public.key")
                    .expect("Failed to create public.key")
                    .write_all(public_key.as_bytes())
                    .expect("Failed to write public key");

                File::create("secret.key")
                    .expect("Failed to create secret.key")
                    .write_all(secret_key.as_bytes())
                    .expect("Failed to write secret key");

                println!("Keys saved to public.key and secret.key");
            }
            else {
                println!("{:?}", keypair);
            }
        }

        Commands::Encrypt {
            pubkey,
            pubkey_file,
            message,
            n,
            q,
            k,
            ciphertext_file,
        } => {
            let params = build_params(*n, *q, *k);

            let pk_string = if let Some(pk) = pubkey {
                pk.clone()
            } else if let Some(file) = pubkey_file {
                fs::read_to_string(file).expect("Failed to read public key file").trim().to_string()
            } else {
                panic!("Must supply either --pubkey or --pubkey-file");
            };

            let ciphertext = encrypt_string(&pk_string, &message, &params, None);

            if let Some(file) = ciphertext_file {
                use std::fs::File;
                use std::io::Write;

                let mut f = File::create(file).expect("Failed to create ciphertext file");
                f.write_all(ciphertext.as_bytes()).expect("Failed to write ciphertext");

                println!("Ciphertext saved to {}", file);
            } else {
                println!("{}", ciphertext);
            }
        }

        Commands::Decrypt {
            secret,
            secret_file,
            ciphertext,
            ciphertext_file,
            n,
            q,
            k,
        } => {
            let params = build_params(*n, *q, *k);

            let sk_string = if let Some(sk) = secret {
                sk.clone()
            } else if let Some(file) = secret_file {
                fs::read_to_string(file).expect("Failed to read secret key file").trim().to_string()
            } else {
                panic!("Must supply either --secret or --secret-file");
            };

            // Load ciphertext from inline arg or file
            let ct_string = if let Some(file) = ciphertext_file {
                fs::read_to_string(file)
                    .expect("Failed to read ciphertext file")
                    .trim()
                    .to_string()
            } else if let Some(ct) = ciphertext {
                ct.clone()
            } else {
                panic!("Must supply either ciphertext or --ciphertext-file");
            };

            let message = decrypt_string(&sk_string, &ct_string, &params);
            println!("{:?}", message);
        }
    }
}

/// Build parameters with default fallback
fn build_params(n: Option<usize>, q: Option<i64>, k: Option<usize>) -> Parameters {
    let mut params = Parameters::default();

    params.n = n.unwrap_or(params.n);
    params.q = q.unwrap_or(params.q);
    params.k = k.unwrap_or(params.k);
    assert!(params.n.is_power_of_two(), "ring degree must be a positive power of two");
    let length = params.n.checked_mul(2).expect("transform length overflow");
    params.omega = crate::utils::root_for_parameters(params.q, length);
    let mut poly_vec = vec![0i64; params.n + 1];
    poly_vec[0] = 1;
    poly_vec[params.n] = 1;
    params.f = Polynomial::new(poly_vec);

    params
}

#[cfg(test)]
mod parameter_consistency_tests {
    use super::build_params;

    fn check(n: Option<usize>, q: Option<i64>, k: Option<usize>, expected_n: usize, expected_q: i64, expected_extra: usize) {
        let params = build_params(n, q, k);
        assert_eq!((params.n, params.q, params.k), (expected_n, expected_q, expected_extra));
        assert_eq!(params.f.coeffs().len(), expected_n + 1);
        assert_eq!(params.f.coeffs()[0], 1);
        assert_eq!(params.f.coeffs()[expected_n], 1);
        assert!(params.f.coeffs()[1..expected_n].iter().all(|&x| x == 0));
        assert!(ntt::verify_root_of_unity(params.omega, (2 * params.n).try_into().unwrap(), params.q));
    }

    #[test]
    fn full_and_partial_overrides_refresh_the_root() {
        check(None, None, None, 512, 12289, 8);
        check(Some(256), Some(7681), Some(4), 256, 7681, 4);
        check(Some(1024), None, None, 1024, 12289, 8);
        check(None, Some(151019521), None, 512, 151019521, 8);
        check(None, None, Some(4), 512, 12289, 4);
    }

    #[test]
    fn invalid_degrees_and_incompatible_moduli_are_rejected() {
        for degree in [0, 3, 1usize << (usize::BITS - 1)] {
            assert!(std::panic::catch_unwind(|| build_params(Some(degree), None, None)).is_err());
        }
        assert!(std::panic::catch_unwind(|| build_params(None, Some(17), None)).is_err());
    }
}
