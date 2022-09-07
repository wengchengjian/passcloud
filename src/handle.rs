use crate::file::write_content;
use crate::request::ReqCommand;
use crate::response::{PullPasswords, ResponseCode, ServerResponse};
use crate::{
    check_authorization, check_authorization_config, decrypt_from_utf8,
    get_auth_path, get_config_path, get_pass_path,
    load_auth_file, load_config, load_pass, Authorization, Config, Password, Passwords, TIME_FMT,
};
use chrono::{DateTime, Local, NaiveDateTime, Utc};
use clipboard::windows_clipboard::WindowsClipboardContext;
use clipboard::ClipboardProvider;
use log::{error, info, warn};
use serde::Serialize;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::tcp::{ReadHalf, WriteHalf};
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

    if let Some(address) = new_config.address {
        config.address = Some(address);
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
                    info!("------ {} -> {}", app, key);
                    if let Some(passwords) = applications.get(&key) {
                        let mut passwords = passwords.clone();
                        // 按照时间降序排序
                        passwords.sort_by(|a, b| {
                            let a_data_time = NaiveDateTime::parse_from_str(&a.timestamp, TIME_FMT)
                                .map(|ndt| DateTime::<Utc>::from_utc(ndt, Utc))
                                .unwrap();

                            let b_data_time = NaiveDateTime::parse_from_str(&b.timestamp, TIME_FMT)
                                .map(|ndt| DateTime::<Utc>::from_utc(ndt, Utc))
                                .unwrap();
                            return b_data_time.timestamp().cmp(&a_data_time.timestamp());
                        });

                        if !last {
                            for pass in passwords {
                                info!(
                                    "------ password: {},version: {} createAt: {}",
                                    String::from(decrypt_from_utf8(&pass.content).trim()),
                                    pass.version,
                                    pass.timestamp
                                );
                            }
                        } else {
                            if let Some(last_pass) = passwords.first() {
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
    let user_pass = load_pass.entry(username).or_insert(HashMap::new());
    // 指定app
    if let Some(app) = app {
        let applications = user_pass.entry(app.clone()).or_insert(HashMap::new());
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

async fn write_cmd<'a, T>(cmd: T, writer: &mut BufWriter<WriteHalf<'a>>)
where
    T: Serialize,
{
    let pass_str = serde_json::to_string(&cmd).expect("序列化返回值失败");

    writer.write_all(&pass_str.as_bytes()).await.unwrap();
    // 写入命令结束标志
    let _ = writer.write_u8(b'\n').await.unwrap();
    writer.flush().await.unwrap();
}

async fn process_request(mut socket: TcpStream, addr: SocketAddr) {
    let ip_addr = addr.ip();

    let (mut reader, writer) = socket.split();

    let mut writer = BufWriter::new(writer);

    let str_req = read_to_string(&mut reader).await;
    let cmd: ReqCommand = serde_json::from_str(&str_req).expect("序列化数据失败!");
    match cmd {
        ReqCommand::Pull { auth } => {
            if check_authorization(&auth) {
                info!(
                    "accept {} request from remote ip: {},username: {}",
                    "pull", ip_addr, auth.username
                );
                let mut load_pass = load_pass().expect("加载密码文件失败");

                let pull_pass = load_pass.entry(auth.username).or_insert(HashMap::new());

                let res = ServerResponse {
                    code: ResponseCode::Success,
                    data: pull_pass,
                    msg: "pull 命令成功".to_string(),
                };
                write_cmd(res, &mut writer).await;
            } else {
                info!("认证失败");
                let res = ServerResponse {
                    code: ResponseCode::Failure,
                    data: (),
                    msg: "认证失败".to_string(),
                };
                write_cmd(res, &mut writer).await;
            }
        }
        ReqCommand::Push { auth, passwords } => {
            if check_authorization(&auth) {
                info!(
                    "accept {} request from remote ip: {},username: {}",
                    "push", ip_addr, auth.username
                );

                let mut load_pass = load_pass().expect("加载密码文件失败");

                for (username, pass) in passwords {
                    load_pass.insert(username, pass);
                }

                let mut file = File::create(get_pass_path().unwrap()).expect("打开密码文件失败");
                // 回写进密码存储文件
                write_content(&mut file, &load_pass).expect("写入密码文件失败");

                let res = ServerResponse {
                    code: ResponseCode::Success,
                    data: (),
                    msg: "push成功".to_string(),
                };

                write_cmd(res, &mut writer).await;
            } else {
                info!("认证失败");
                let res = ServerResponse {
                    code: ResponseCode::Failure,
                    data: (),
                    msg: "认证失败".to_string(),
                };
                write_cmd(res, &mut writer).await;
            }
        }
        ReqCommand::Stop { auth } => {
            if check_authorization(&auth) {
                info!(
                    "accept {} request from remote ip: {},username: {}",
                    "stop", ip_addr, auth.username
                );

                info!("server is stopping");
                unsafe {
                    RUNNING.store(false, Ordering::Relaxed);
                }
                let res = ServerResponse {
                    code: ResponseCode::Success,
                    data: (),
                    msg: "关闭成功".to_string(),
                };
                write_cmd(res, &mut writer).await;
            } else {
                info!("认证失败");
                let res = ServerResponse {
                    code: ResponseCode::Failure,
                    data: (),
                    msg: "认证失败".to_string(),
                };
                write_cmd(res, &mut writer).await;
            }
        }
        ReqCommand::Register { auth } => {
            info!(
                "accept {} request from remote ip: {},username: {}",
                "register", ip_addr, auth.username
            );

            let mut load_auth = load_auth_file().expect("加载认证文件失败!");
            load_auth.insert(auth.username, auth.password);

            let mut file = File::create(get_auth_path().unwrap()).expect("打开密码文件失败");
            // 回写进密码存储文件
            write_content(&mut file, &load_auth).expect("写入认证文件失败");

            let res = ServerResponse {
                code: ResponseCode::Success,
                data: (),
                msg: "register成功".to_string(),
            };
            write_cmd(res, &mut writer).await;
        }
    }
}

pub static mut RUNNING: AtomicBool = AtomicBool::new(true);

pub async fn handle_start_cloud_server(config: &Config) {
    if let Some(address) = &config.address {
        info!("pass cloud server is starting...");
        let listener = TcpListener::bind(address).await.unwrap();
        info!("pass cloud server listening on {}", address);
        unsafe {
            loop {
                let (socket, addr) = listener.accept().await.unwrap();
                let task = tokio::spawn(async move {
                    process_request(socket, addr).await;
                });
                if !RUNNING.load(Ordering::Acquire) && !task.is_finished() {
                    //阻塞直到最后一个任务完成
                    task.await.expect("last task failed before server stopped");
                    break;
                }
            }
        }
        info!("pass cloud server is stopped ")
    }
}
pub async fn handle_stop_cloud_server() {
    unsafe {
        info!("pass cloud server is stopping");
        RUNNING.store(false, Ordering::Release);
    }
}

pub async fn read_to_string<'a>(stream: &mut ReadHalf<'a>) -> String {
    // 读取缓冲区数据
    let mut buffer = Vec::new();

    let mut reader = BufReader::new(stream);
    let _ = reader.read_until(b'\n', &mut buffer).await.unwrap();
    let res_str = String::from_utf8(buffer).expect("读取utf字符串失败");

    return res_str;
}

pub async fn handle_pull_pass(config: &Config) {
    if check_authorization_config() {
        if let Some(address) = &config.cloud_address {
            // 组织push命令结构
            let auth = Authorization {
                username: config.username.clone().unwrap(),
                password: config.password.clone().unwrap(),
            };
            let cmd = ReqCommand::Pull { auth };
            // 连接server
            let mut stream = TcpStream::connect(address).await.unwrap();
            info!("connected server: {} successful", address);

            let (mut reader, writer) = stream.split();
            let mut writer = BufWriter::new(writer);
            info!("sending pull command...");
            write_cmd(cmd, &mut writer).await;
            info!("waiting for server response...");

            let res_str = read_to_string(&mut reader).await;
            let cmd: ServerResponse<PullPasswords> =
                serde_json::from_str(&res_str).expect("序列化服务器返回值失败");

            handle_request_data(cmd, |_| {}, handle_rewrite_pass_file);
        }
    } else {
        error!("server地址为空");
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
            info!("请求服务器成功,消息:{}", cmd.msg);
            handle_success(cmd.data);
        }
    }
}

pub async fn handle_push_pass(config: &Config, passwords: Passwords) {
    if check_authorization_config() {
        if let Some(address) = &config.cloud_address {
            // 组织push命令结构
            let auth = Authorization {
                username: config.username.clone().unwrap(),
                password: config.password.clone().unwrap(),
            };
            let cmd = ReqCommand::Push { auth, passwords };
            // 连接server
            let mut stream = TcpStream::connect(address).await.unwrap();

            info!("connected server: {} successful", address);

            let (mut reader, writer) = stream.split();

            let mut writer = BufWriter::new(writer);
            info!("sending push command...");
            write_cmd(cmd, &mut writer).await;
            // 接收server返回值
            let res_str = read_to_string(&mut reader).await;
            info!("waiting for server response...");
            let cmd: ServerResponse<()> =
                serde_json::from_str(&res_str).expect("序列化服务器返回值失败");
            handle_request_data(cmd, |_s| {}, |_s| {});
        }
    } else {
        error!("server地址为空");
    }
}

pub async fn handle_register_pass(config: &Config) {
    if check_authorization_config() {
        if let Some(address) = &config.cloud_address {
            // 组织push命令结构
            let auth = Authorization {
                username: config.username.clone().unwrap(),
                password: config.password.clone().unwrap(),
            };
            let cmd = ReqCommand::Register { auth };
            // 连接server
            let mut stream = TcpStream::connect(address).await.unwrap();
            info!("connected server: {} successful", address);

            let (mut reader, writer) = stream.split();
            let mut writer = BufWriter::new(writer);
            info!("sending register command...");
            write_cmd(cmd, &mut writer).await;
            info!("waiting for server response...");
            // 接收server返回值
            let res_str = read_to_string(&mut reader).await;
            let cmd: ServerResponse<()> =
                serde_json::from_str(&res_str).expect("序列化服务器返回值失败");

            handle_request_data(cmd, |_s| {}, |_s| {});
        }
    }
}

pub async fn handle_stop_pass(config: &Config) {
    if check_authorization_config() {
        if let Some(address) = &config.cloud_address {
            // 组织push命令结构
            let auth = Authorization {
                username: config.username.clone().unwrap(),
                password: config.password.clone().unwrap(),
            };
            let cmd = ReqCommand::Stop { auth };
            // 连接server
            let mut stream = TcpStream::connect(address).await.unwrap();
            info!("connected server: {} successful", address);

            let (mut reader, writer) = stream.split();
            let mut writer = BufWriter::new(writer);
            info!("sending stop command...");
            write_cmd(cmd, &mut writer).await;
            info!("waiting for server response...");
            // 接收server返回值
            let res_str = read_to_string(&mut reader).await;
            let cmd: ServerResponse<()> =
                serde_json::from_str(&res_str).expect("序列化服务器返回值失败");

            handle_request_data(cmd, |_s| {}, |_s| {});
        }
    }
}
