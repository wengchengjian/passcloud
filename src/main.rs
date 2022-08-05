use clap::Parser;
use passcloud;
use passcloud::{Commands, Config};
use passwords::analyzer;
use passwords::scorer;
use passwords::PasswordGenerator;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

const CONFIG_FILE: &'static str = "config.json";

fn main() {
    let cli = passcloud::Cli::parse();

    let mut config = Config::new();

    let config_file_path = Path::new(CONFIG_FILE);

    if config_file_path.exists() {
        match Config::from_path(&config_file_path) {
            Ok(new_config) => {
                config = new_config;
                println!("Config file:{:?}", config)
            }
            Err(e) => {
                println!("Read Config file Failed,Reason:{:?}", e);
            }
        }
    } else {
        println!("No config file found");
        match File::create(config_file_path) {
            Ok(mut file) => {
                println!(
                    "Will create default config file in path:{:?}",
                    fs::canonicalize(config_file_path).unwrap()
                );
                match write_default_config_content(&mut file) {
                    Ok(_) => {
                        config =
                            Config::from_path(&config_file_path).expect("Read Config File failed");
                        println!("Created default config file success")
                    }
                    Err(e) => println!("Create default config failed,Reason:{:?}", e),
                }
            }
            Err(e) => {
                println!("Failed to open config file,Reason:{:?}", e);
            }
        }
    }

    if let Some(passpath) = cli.passpath.as_deref() {
        let mut file = File::open(&config_file_path).expect("Failed to open config file");
        config.passpath = Some(PathBuf::from(passpath));
        match write_config_content(&mut file, &config) {
            Ok(_) => {
                println!("Set Passpath Success")
            }
            Err(e) => {
                println!("Set Passpath Failed,Reason:{:?}", e);
            }
        }
    }

    if let Some(command) = cli.command {
        match command {
            Commands::GET { key } => {
                if let Some(key) = key {
                    println!("Not Found: {}", key);
                } else {
                    println!("Key is Empty");
                }
            }
            Commands::SET { key, password } => {
                if let Some(key) = key {
                    if let Some(password) = password {
                        println!("Set key: {},password: {} Success", key, password);
                    } else {
                        println!("Password is Empty");
                    }
                } else {
                    println!("Key is Empty");
                }
            }
            Commands::GEN { key, length } => {
                let mut pass_length = 12;

                if let Some(length) = length {
                    pass_length = length;
                }

                if let Some(key) = key {
                    let pg = get_password_generator(pass_length);

                    match pg.generate_one() {
                        Ok(password) => {
                            println!("generate password: {} for key: {}", password, key);
                            let score = scorer::score(&analyzer::analyze(password));
                            function_score(score);
                        }
                        Err(e) => {
                            println!("generate password error,reason:{}", e)
                        }
                    }
                } else {
                    println!("Key is Empty");
                }
            }
        }
    } else {
        println!("Command not found");
    }
}

fn write_default_config_content(file: &mut File) -> Result<(), Box<dyn Error>> {
    let config = Config::new();
    write_config_content(file, &config)?;
    Ok(())
}

fn write_config_content(file: &mut File, config: &Config) -> Result<(), Box<dyn Error>> {
    let content = serde_json::to_string(&config)?;
    file.write(content.as_bytes())?;
    file.flush()?;
    Ok(())
}

fn get_password_generator(len: usize) -> PasswordGenerator {
    PasswordGenerator {
        length: len,
        numbers: true,
        lowercase_letters: true,
        uppercase_letters: true,
        symbols: false,
        spaces: false,
        exclude_similar_characters: false,
        strict: true,
    }
}

fn function_score(score: f64) {
    match score {
        score if score <= 20f64 => {
            println!("your password is very dangerous (may be cracked within few seconds)")
        }
        score if score <= 40f64 => {
            println!("your password is dangerous")
        }
        score if score <= 60f64 => {
            println!("your password is very weak")
        }
        score if score <= 80f64 => {
            println!("your password is weak")
        }
        score if score <= 90f64 => {
            println!("your password is good")
        }
        score if score <= 95f64 => {
            println!("your password is strong")
        }
        score if score <= 99f64 => {
            println!("your password is very strong")
        }
        score if score <= 100f64 => {
            println!("your password is invulnerable")
        }
        _ => {}
    }
}
