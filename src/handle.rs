use crate::file::write_content;
use crate::{
    decrypt_from_utf8, get_config_path, get_pass_file_path, get_pass_home, get_pass_path,
    load_pass, Authorization, Config, Password, Passwords, TIME_FMT,
};
use chrono::{DateTime, Local, NaiveDateTime, TimeZone, Utc};
use clipboard::windows_clipboard::WindowsClipboardContext;
use clipboard::ClipboardProvider;
use serde::{Deserialize, Serialize, Serializer};
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

pub fn handle_pass_config_cli(config: &mut Config, new_config: Config) {
    if let Some(username) = new_config.username {
        config.username = Some(username);
    }

    if let Some(password) = new_config.password {
        config.password = Some(password);
    }

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

pub fn handle_get_cli(load_pass: &Passwords, app: Option<String>, key: Option<String>, last: bool) {
    if let Some(app) = app {
        // 列出该应用下的所有密码
        if let Some(applications) = load_pass.get(&app) {
            if let Some(key) = key {
                println!("{} -> {}", app, key);
                if let Some(passwords) = applications.get(&key) {
                    if !last {
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
                            let password =
                                String::from(decrypt_from_utf8(&last_pass.content).trim());
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
        } else {
            println!("无此应用:{}", app);
        }
    } else {
        println!("App is Empty")
    }
}

pub fn handle_set_cli(
    load_pass: &mut Passwords,
    app: &Option<String>,
    key: &Option<String>,
    password: Option<String>,
) -> Result<(), Box<dyn Error>> {
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

                let mut file = File::create(get_pass_path().unwrap())?;
                // 回写进密码存储文件
                write_content(&mut file, load_pass)?;
            } else {
                println!("密码不能为空");
            }
        } else {
            println!("Key is Empty!");
        }
    } else {
        println!("App is Empty")
    }

    Ok(())
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ReqCommand {
    Push {
        auth: Authorization,
        passwords: Passwords,
    },
    Pull {
        auth: Authorization,
    },
}

async fn process_request(mut socket: TcpStream) {
    let mut str_req = String::new();
    socket
        .read_to_string(&mut str_req)
        .await
        .expect("读取请求数据失败");
    let cmd: ReqCommand = serde_json::from_str(&str_req).expect("序列化数据失败!");
    match cmd {
        ReqCommand::Pull { auth } => {}
        ReqCommand::Push { auth, passwords } => {}
    }
}

pub async fn handle_start_cloud_server(config: &Config) {
    let listener = TcpListener::bind("127.0.0.1:7898").await.unwrap();

    loop {
        let (socket, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            process_request(socket).await;
        });
    }
}
pub async fn handle_stop_cloud_server() {}

pub async fn handle_pull_pass(config: &Config) {}

pub async fn handle_push_pass(config: &Config, pass: Passwords) {}
