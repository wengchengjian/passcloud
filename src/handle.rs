use crate::file::write_content;
use crate::request::ReqCommand;
use crate::response::{PullPasswords, ResponseCode, ServerResponse};
use crate::{
    check_authorization, check_authorization_config, check_common_config, decrypt_from_utf8,
    get_config_path, get_pass_file_path, get_pass_home, get_pass_path, load_config, load_pass,
    Authorization, Config, Password, Passwords, TIME_FMT,
};
use chrono::{DateTime, Local, NaiveDateTime, TimeZone, Utc};
use clipboard::windows_clipboard::WindowsClipboardContext;
use clipboard::ClipboardProvider;
use log::{error, info, warn};
use serde::{Deserialize, Serialize, Serializer};
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

pub fn handle_get_cli(
    load_pass: &Passwords,
    load_config: &Config,
    app: Option<String>,
    key: Option<String>,
    last: bool,
) {
    let username = (&load_config.username).clone().unwrap();

    if let Some(load_pass) = load_pass.get(&username) {
        if let Some(app) = app {
            // 列出该应用下的所有密码
            if let Some(applications) = load_pass.get(&app) {
                if let Some(key) = key {
                    info!("{} -> {}", app, key);
                    if let Some(passwords) = applications.get(&key) {
                        if !last {
                            for pass in passwords {
                                info!(
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
                                info!(
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
                        info!("{} -> {}", app, key);
                        for pass in passwords {
                            info!(
                                "------ password:{},version:{} createAt:{}",
                                decrypt_from_utf8(&pass.content),
                                pass.version,
                                pass.timestamp
                            );
                        }
                    }
                }
            } else {
                warn!("无此应用:{}", app);
            }
        } else {
            warn!("App is Empty")
        }
    }
}

pub fn handle_set_cli(
    load_pass: &mut Passwords,
    load_config: &Config,
    app: &Option<String>,
    key: &Option<String>,
    password: Option<String>,
) -> Result<(), Box<dyn Error>> {
    let username = (&load_config.username).clone().unwrap();

    //指定用户
    let load_pass = load_pass.entry(username).or_insert(HashMap::new());
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
                warn!("密码不能为空");
            }
        } else {
            warn!("Key is Empty!");
        }
    } else {
        warn!("App is Empty")
    }

    Ok(())
}

async fn process_request(mut socket: TcpStream) {
    let mut str_req = String::new();
    socket
        .read_to_string(&mut str_req)
        .await
        .expect("读取请求数据失败");
    let cmd: ReqCommand = serde_json::from_str(&str_req).expect("序列化数据失败!");
    match cmd {
        ReqCommand::Pull { auth } => {
            if check_authorization(&auth) {
            } else {
                info!("认证失败");
            }
        }
        ReqCommand::Push { auth, passwords } => {
            if check_authorization(&auth) {
            } else {
                info!("认证失败");
            }
        }
    }
}

pub async fn handle_start_cloud_server(config: &Config) {
    match load_config() {
        Err(e) => {
            error!("加载配置文件失败,原因:{}", e);
        }
        Ok(config) => {
            if let Some(address) = config.address {
                let listener = TcpListener::bind(address).await.unwrap();
                loop {
                    let (socket, _) = listener.accept().await.unwrap();
                    tokio::spawn(async move {
                        process_request(socket).await;
                    });
                }
            } else {
                error!("server启动地址为空");
            }
        }
    }
}
pub async fn handle_stop_cloud_server() {
    match load_config() {
        Err(e) => {
            error!("加载配置文件失败,原因:{}", e);
        }
        Ok(config) => {
            if let Some(address) = config.address {
                let listener = TcpListener::bind(address).await.unwrap();
                loop {
                    let (socket, _) = listener.accept().await.unwrap();
                    tokio::spawn(async move {
                        process_request(socket).await;
                    });
                }
            } else {
                error!("server启动地址为空");
            }
        }
    }
}

pub async fn handle_pull_pass(config: &Config) {
    match load_config() {
        Err(e) => {
            error!("加载配置文件失败,原因:{}", e);
        }
        Ok(config) => {
            if check_authorization_config() {
                if let Some(address) = config.cloud_address {
                    // 组织push命令结构
                    let auth = Authorization {
                        username: config.username.unwrap().clone(),
                        password: config.password.unwrap().clone(),
                    };
                    let cmd = ReqCommand::Pull { auth };
                    // 连接server
                    let mut listener = TcpStream::connect(address).await.unwrap();

                    let bytes = serde_json::to_vec(&cmd).expect("序列化pull命令失败");
                    // 发送pull命令
                    let _ = listener.write_all(&bytes).await.unwrap();

                    // 接收server返回值
                    let mut res_str = String::new();
                    listener.read_to_string(&mut res_str).await.unwrap();

                    let cmd: ServerResponse<PullPasswords> =
                        serde_json::from_str(&res_str).expect("序列化服务器返回值失败");

                    handle_request_data(cmd, |pass| {}, handle_rewrite_pass_file);
                }
            } else {
                error!("server地址为空");
            }
        }
    }
}

pub fn handle_rewrite_pass_file(pass: PullPasswords) {
    let mut load_pass = load_pass().expect("加载密码文件失败");

    let load_config = load_config().expect("加载配置文件失败");

    let username = load_config.username.expect("用户名不能为空");

    load_pass.insert(username, pass);

    let mut file = File::create(get_pass_path().unwrap()).expect("打开密码文件失败");
    // 回写进密码存储文件
    write_content(&mut file, &load_pass).expect("写入密码文件失败");
}

pub fn handle_request_data<T, F1, F2>(
    cmd: ServerResponse<T>,
    handle_failure: F1,
    handle_success: F2,
) where
    F1: FnOnce(T),
    F2: FnOnce(T),
{
    match cmd.code {
        ResponseCode::Failure => {
            error!("请求服务器失败,原因:{}", cmd.msg);
            handle_failure(cmd.data);
        }
        ResponseCode::Success => {
            info!("请求服务器失败,原因:{}", cmd.msg);
            handle_success(cmd.data);
        }
    }
}

pub async fn handle_push_pass(config: &Config, pass: Passwords) {
    match load_config() {
        Err(e) => {
            error!("加载配置文件失败,原因:{}", e);
        }
        Ok(config) => {
            if check_authorization_config() {
                if let Some(address) = config.cloud_address {
                    match load_pass() {
                        Ok(passwords) => {
                            // 组织push命令结构
                            let auth = Authorization {
                                username: config.username.unwrap().clone(),
                                password: config.password.unwrap().clone(),
                            };
                            let cmd = ReqCommand::Push { auth, passwords };
                            // 连接server
                            let mut listener = TcpStream::connect(address).await.unwrap();

                            let bytes = serde_json::to_vec(&cmd).expect("序列化push命令失败");
                            // 发送push命令
                            let _ = listener.write_all(&bytes).await.unwrap();

                            // 接收server返回值
                            let mut res_str = String::new();
                            listener.read_to_string(&mut res_str).await.unwrap();
                            let cmd: ServerResponse<()> =
                                serde_json::from_str(&res_str).expect("序列化服务器返回值失败");

                            handle_request_data(cmd, |s| {}, |s| {});
                        }
                        Err(_) => {
                            error!("加载密码文件失败")
                        }
                    }
                } else {
                    error!("server地址为空");
                }
            }
        }
    }
}
