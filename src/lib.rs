use chrono::{Date, DateTime, Local};
use clap::{Parser, Subcommand};
use passwords::{analyzer, scorer, PasswordGenerator};
use serde::{Deserialize, Serialize, Serializer};
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::{env, fs};

mod encrypt;
pub mod file;
pub mod handle;

#[derive(Parser)]
#[clap(author = "wengchengjian", version = "1.0.0", about = "密码管理工具", long_about = None)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Option<Commands>,
}

pub type Passwords = HashMap<String, HashMap<String, Vec<Password>>>;

#[derive(Subcommand)]
pub enum Commands {
    GET {
        /// 应用
        #[clap(value_parser)]
        app: Option<String>,

        /// key可以是账号，或者某个关键词
        #[clap(value_parser)]
        key: Option<String>,
        #[clap(long, value_parser, default_value = "true")]
        last: bool,
    },
    SET {
        /// 应用
        #[clap(value_parser, value_name = "APP")]
        app: Option<String>,
        /// 关键词
        #[clap(value_name = "KEY")]
        key: Option<String>,
        /// 密码
        #[clap(value_name = "PASSWORD")]
        password: Option<String>,
    },
    GEN {
        /// 应用
        #[clap(value_parser, value_name = "APP")]
        app: Option<String>,
        /// 关键词
        #[clap(value_parser, value_name = "KEY")]
        key: Option<String>,
        /// 密码长度
        #[clap(short, long, action)]
        length: Option<usize>,
    },
    CONFIG {
        #[clap(long, value_parser, value_name = "OFFLINE")]
        offline: bool,

        #[clap(long, value_parser, value_name = "DEBUG")]
        debug: bool,

        #[clap(long, value_parser, value_name = "CLOUD_ADDRESS")]
        cloud_address: Option<String>,

        #[clap(short, long, value_parser, value_name = "USERNAME")]
        username: Option<String>,

        #[clap(short, long, value_parser, value_name = "PASSWORD")]
        password: Option<String>,

        #[clap(long, value_parser, value_name = "CONFIG")]
        config: Option<PathBuf>,
    },
}

pub const TIME_FMT: &str = "%Y年%m月%d日 %H:%M:%S";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Password {
    pub content: Vec<u8>,
    pub encrypter: Encrypter,
    pub version: u8,
    pub timestamp: String,
}

impl Password {
    pub fn new(password: String) -> Self {
        Password {
            content: encrypt::encrypt(password.as_bytes()).expect("加密失败"),
            encrypter: Encrypter::AES,
            version: 0,
            timestamp: Local::now().format(TIME_FMT).to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Encrypter {
    AES,
    DES,
}

pub const PASSPATH: &str = "\\.password";

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub offline: bool,

    pub debug: bool,

    pub cloud_address: Option<String>,

    pub username: Option<String>,

    pub password: Option<String>,
}

impl Config {
    pub fn new() -> Self {
        Self {
            offline: true,
            debug: false,
            cloud_address: Some(String::new()),
            username: Some(String::new()),
            password: Some(String::new()),
        }
    }

    pub fn from_args(
        offline: bool,
        debug: bool,
        cloud_address: Option<String>,
        username: Option<String>,
        password: Option<String>,
    ) -> Self {
        Self {
            offline,
            debug,
            cloud_address,
            username,
            password,
        }
    }

    pub fn from_file(file: &mut File) -> Result<Config, Box<dyn Error>> {
        let mut str = String::new();
        file.read_to_string(&mut str)?;
        let config: Config = serde_json::from_str(&str)?;
        Ok(config)
    }

    pub fn from_path(path: &Path) -> Result<Config, Box<dyn Error>> {
        let str = fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&str)?;
        Ok(config)
    }
}

pub fn get_password_generator(len: usize) -> PasswordGenerator {
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

pub fn function_score(password: &str) {
    let score = scorer::score(&analyzer::analyze(password));

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

pub const CONFIG_FILE: &'static str = "\\.passrc";

pub fn load_config() -> Result<Config, Box<dyn Error>> {
    fs::create_dir_all(Path::new(&get_pass_home().unwrap()))?;
    // 创建一个默认的配置
    Ok(file::load_content(
        &get_config_path().unwrap(),
        Some(Config::new()),
    )?)
}

pub fn load_pass() -> Result<Passwords, Box<dyn Error>> {
    fs::create_dir_all(Path::new(&get_pass_home().unwrap()))?;
    // 创建一个默认的密码文件
    Ok(file::load_content(
        &get_pass_path().unwrap(),
        Some(Passwords::new()),
    )?)
}

pub fn get_pass_home() -> Option<String> {
    let env_vars: HashMap<String, String> = env::vars().collect();
    return Some(env_vars.get("PASS_HOME").unwrap().clone());
}

pub fn get_config_path() -> Option<String> {
    return get_pass_file_path(CONFIG_FILE);
}

pub fn get_pass_file_path(re_path: &str) -> Option<String> {
    if let Some(path) = get_pass_home() {
        let mut str = String::from(path);
        str.push_str(re_path);
        return Some(str);
    } else {
        None
    }
}
pub fn get_pass_path() -> Option<String> {
    return get_pass_file_path(PASSPATH);
}

pub fn decrypt_from_utf8(arr: &Vec<u8>) -> String {
    String::from_utf8(encrypt::decrypt(&arr).expect("解密失败")).expect("字节数组转字符串失败")
}
