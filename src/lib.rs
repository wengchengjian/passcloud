use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[clap(author = "wengchengjian", version = "1.0.0", about = "密码管理工具", long_about = None)]
pub struct Cli {
    #[clap(short, long, value_parser, value_name = "FILE")]
    pub passpath: Option<PathBuf>,
    #[clap(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Application {
    name: String,
    password: Vec<Password>,
}

#[derive(Subcommand)]
pub enum Commands {
    GET {
        #[clap(short, long, action)]
        key: Option<String>,
    },
    SET {
        #[clap(short, long, action)]
        key: Option<String>,

        #[clap(short, long, action)]
        password: Option<String>,
    },
    GEN {
        #[clap(short, long, action)]
        key: Option<String>,

        #[clap(short, long, action)]
        length: Option<usize>,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Password {
    name: String,
    encrypter: Encrypter,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Encrypter {
    AES,
    DES,
}

pub const PASSPATH: &str = "~/.password";

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    /// 本地密码存储文件地址
    pub passpath: Option<PathBuf>,
    /// 是否开启离线模式
    pub offline: bool,
    /// 云端地址
    pub cloud_address: Option<String>,
    /// 云端用户名
    pub username: Option<String>,
    /// 云端密码
    pub password: Option<String>,
}

impl Config {
    pub fn new() -> Self {
        Self {
            passpath: Some(PathBuf::from(PASSPATH)),
            offline: true,
            cloud_address: Some(String::new()),
            username: Some(String::new()),
            password: Some(String::new()),
        }
    }

    pub fn from_path(path: &Path) -> Result<Config, Box<dyn Error>> {
        let str = fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&str)?;
        Ok(config)
    }
}
