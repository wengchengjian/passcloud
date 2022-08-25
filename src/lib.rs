use chrono::{Date, DateTime, Local};
use clap::{Parser, Subcommand};
use log::{error, info, warn};
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
mod response;
mod request;

#[derive(Parser)]
#[clap(author = "wengchengjian", version = "1.0.0", about = "密码管理工具", long_about = None)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Option<Commands>,
}

// user->(app->(key->vec<pass>))
pub type Passwords = HashMap<String, HashMap<String, HashMap<String, Vec<Password>>>>;

#[derive(Subcommand)]
pub enum Commands {
    Get {
        /// 应用
        #[clap(value_parser)]
        app: Option<String>,

        /// key可以是账号，或者某个关键词
        #[clap(value_parser)]
        key: Option<String>,
        #[clap(long, value_parser, default_value = "true")]
        last: bool,
    },
    Set {
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
    Gen {
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
    Config {
        #[clap(long, value_parser, value_name = "CLOUD_ADDRESS")]
        cloud_address: Option<String>,

        #[clap(short, long, value_parser, value_name = "USERNAME")]
        username: Option<String>,

        #[clap(short, long, value_parser, value_name = "PASSWORD")]
        password: Option<String>,

        #[clap(long, value_parser, value_name = "CONFIG")]
        config: Option<PathBuf>,

        #[clap(long, value_parser, value_name = "ADDRESS")]
        address: Option<String>,
    },
    Client {
        #[clap(subcommand)]
        cmd: ClientSubCmd,
    },
    Server {
        #[clap(subcommand)]
        cmd: ServerSubCmd,
    },
}

pub type Authorizations = HashMap<String, String>;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Authorization {
    username: String,
    password: String,
}

#[derive(Subcommand, Clone)]
pub enum ClientSubCmd {
    Push,
    Pull,
}

#[derive(Subcommand, Clone)]
pub enum ServerSubCmd {
    Start,
    Stop,
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

pub const AUTHPATH: &str = "\\.authorization";

pub const DEFAULT_ADDRESS: &str = "127.0.0.1:7879";

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub cloud_address: Option<String>,

    pub address: Option<String>,

    pub username: Option<String>,

    pub password: Option<String>,
}

impl Config {
    pub fn new() -> Self {
        Self {
            cloud_address: Some(String::new()),
            username: Some(String::new()),
            password: Some(String::new()),
            address: Some(String::from(DEFAULT_ADDRESS)),
        }
    }

    pub fn from_args(
        cloud_address: Option<String>,
        username: Option<String>,
        password: Option<String>,
        address: Option<String>,
    ) -> Self {
        Self {
            cloud_address,
            username,
            password,
            address,
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
            warn!("your password is very dangerous (may be cracked within few seconds)")
        }
        score if score <= 40f64 => {
            warn!("your password is dangerous")
        }
        score if score <= 60f64 => {
            warn!("your password is very weak")
        }
        score if score <= 80f64 => {
            warn!("your password is weak")
        }
        score if score <= 90f64 => {
            info!("your password is good")
        }
        score if score <= 95f64 => {
            info!("your password is strong")
        }
        score if score <= 99f64 => {
            info!("your password is very strong")
        }
        _ => {
            info!("your password is invulnerable")
        }
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

pub fn load_auth_file() -> Result<Authorizations, Box<dyn Error>> {
    fs::create_dir_all(Path::new(&get_pass_home().unwrap()))?;
    // 创建一个默认的密码文件
    Ok(file::load_content(
        &get_auth_path().unwrap(),
        Some(Authorizations::new()),
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

pub fn get_auth_path() -> Option<String> {
    return get_pass_file_path(AUTHPATH);
}

pub fn decrypt_from_utf8(arr: &Vec<u8>) -> String {
    String::from_utf8(encrypt::decrypt(&arr).expect("解密失败")).expect("字节数组转字符串失败")
}

pub fn check_authorization(auth: &Authorization) -> bool {
    match load_auth_file() {
        Err(e) => {
            error!("加载认证密码文件失败,原因:{}", e);
            false
        }
        Ok(authorizations) => {
            if authorizations.contains_key(&auth.username) {
                if let Some(password) = authorizations.get(&auth.username) {
                    return password.eq(&auth.password);
                } else {
                    false
                }
            } else {
                false
            }
        }
    }
}

pub fn check_authorization_config() -> bool {
    match load_config() {
        Err(e) => {
            error!("加载配置文件失败,原因:{}", e);
            false
        }
        Ok(config) => {
            if let Some(_) = config.username {
                if let Some(_) = config.password {
                    true
                } else {
                    error!("密码不能为空");
                    false
                }
            } else {
                error!("用户名不能为空");
                false
            }
        }
    }
}

pub fn check_common_config(config: &Config) -> Result<(), String> {
    if let Some(username) = &config.username {
        if username.is_empty() {
            Err(String::from("用户名不能为空"))
        } else {
            Ok(())
        }
    } else {
        Err(String::from("用户名不能为空"))
    }
}

pub fn check_cloud_config(config: &Config) -> Result<(), String> {
    if let Some(address) = &config.cloud_address {
        if address.is_empty() {
            Err(String::from("云端地址不能为空"))
        } else {
            if let Some(username) = &config.username {
                if username.is_empty() {
                    Err(String::from("用户名不能为空"))
                } else {
                    if let Some(password) = &config.password {
                        if password.is_empty() {
                            Err(String::from("密码不能为空"))
                        } else {
                            Ok(())
                        }
                    } else {
                        Err(String::from("密码不能为空"))
                    }
                }
            } else {
                Err(String::from("用户名不能为空"))
            }
        }
    } else {
        Err(String::from("云端地址不能为空"))
    }
}
