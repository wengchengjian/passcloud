use crate::file::write_content;
use crate::{
    decrypt_from_utf8, get_config_path, get_pass_path, Config, Password, Passwords, TIME_FMT,
};
use chrono::{DateTime, Local, NaiveDateTime, Utc};
use clipboard::windows_clipboard::WindowsClipboardContext;
use clipboard::ClipboardProvider;
use std::collections::HashMap;
use std::fs::File;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::stream::StreamExt;

pub fn handle_pass_config_cli(config: &mut Config, new_config: Config) {
    config.debug = new_config.debug;

    if let Some(username) = new_config.username {
        config.username = Some(username);
    }

    if let Some(password) = new_config.password {
        config.password = Some(password);
    }

    config.offline = new_config.offline;

    if let Some(cloud_address) = new_config.cloud_address {
        config.cloud_address = Some(cloud_address);
    }
    let mut file = File::create(get_config_path().expect("PASS_HOME环境变量未设置"))
        .expect("获取配置文件失败！");
    write_content(&mut file, &config).expect("配置写入失败！");
}

pub fn get_last_password(passwords: &Vec<Password>) -> Option<Password> {
    let mut min_timestamp: i64 = i64::MAX;

    let mut password: Option<Password> = None;

    let now_time = Local::now().timestamp();
    for pass in passwords {
        let data_time = NaiveDateTime::parse_from_str(&pass.timestamp, TIME_FMT)
            .map(|ndt| DateTime::<Utc>::from_utc(ndt, Utc))
            .unwrap();
        let new_time_stamp = now_time - data_time.timestamp();
        if new_time_stamp < min_timestamp {
            min_timestamp = new_time_stamp;
            password = Some((*pass).clone());
        }
    }
    return password;
}

pub fn handle_get_cli(
    load_pass: &Passwords,
    app: String,
    key: Option<String>,
    list: bool,
) -> Result<(), String> {
    // 列出该应用下的所有密码
    if let Some(applications) = load_pass.get(&app) {
        if let Some(key) = key {
            println!("{} -> {}", app, key);
            if let Some(passwords) = applications.get(&key) {
                if list {
                    for pass in passwords {
                        println!(
                            "------ password:{},version:{} createAt:{}",
                            String::from(decrypt_from_utf8(&pass.content).trim()),
                            pass.version,
                            pass.timestamp
                        );
                    }
                } else {
                    if let Some(last_pass) = get_last_password(passwords) {
                        let password = String::from(decrypt_from_utf8(&last_pass.content).trim());
                        println!(
                            "------ latest password:{},version:{} createAt:{}",
                            password, last_pass.version, last_pass.timestamp
                        );
                        let mut provider = WindowsClipboardContext::new().unwrap();
                        provider
                            .set_contents(password)
                            .expect("复制密码到缓冲区失败");
                    }
                }
            }
        } else {
            for (key, passwords) in applications {
                println!("{} -> {}", app, key);
                for pass in passwords {
                    println!(
                        "------ password:{},version:{} createAt:{}",
                        decrypt_from_utf8(&pass.content),
                        pass.version,
                        pass.timestamp
                    );
                }
            }
        }
    }

    Ok(())
}

pub fn handle_set_cli(
    load_pass: &mut Passwords,
    app: &Option<String>,
    key: &Option<String>,
    password: Option<String>,
) -> Result<(), String> {
    // 指定app
    if let Some(app) = app {
        let applications = load_pass.entry(app.clone()).or_insert(HashMap::new());
        // 指定key,必须
        if let Some(key) = key {
            // 密码必须
            if let Some(password) = password {
                let passwords = applications.entry(key.clone()).or_insert(Vec::new());
                let mut password = Password::new(password);
                // 默认版本会加1,如果不是第一次添加
                if let Some(last_pass) = get_last_password(passwords) {
                    password.version = last_pass.version + 1;
                }
                passwords.push(password);

                let mut file = File::create(get_pass_path().unwrap())
                    .map_err(|_| String::from("密码文件打开失败"))?;
                // 回写进密码存储文件
                write_content(&mut file, load_pass).map_err(|_| String::from("密码存储失败"))?;
            } else {
                return Err(String::from("密码为空"));
            }
        } else {
            return Err(String::from("key不能为空"));
        }
    } else {
        return Err(String::from("应用不能为空"));
    }
    Ok(())
}

pub fn handle_push_pass(config: &Config, pass: &Passwords) {}

pub fn handle_pull_pass(config: &Config, pass: &Passwords) {}

const ADDRESS: &str = "127.0.0.1:9786";

pub async fn start_async_server() {
    let listener = TcpListener::bind(ADDRESS).await.unwrap();
    loop {
        let (stream, socket) = listener.accept().await.unwrap();
        let handle = tokio::spawn(async move {
            process(stream).await;
        });
    }
}

async fn process(socket: TcpStream) {}
