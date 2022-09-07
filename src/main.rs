extern crate core;

use clap::Parser;
use env_logger::{Builder, Target};
use log::{error, info, warn, LevelFilter};
use passcloud;
use passcloud::{
    check_cloud_config, get_pass_home, handle, ClientSubCmd, Commands, Config,
    ServerSubCmd,
};

fn init_log() {
    let mut builder = Builder::from_default_env();
    builder.target(Target::Stdout);
    builder.filter_level(LevelFilter::Info);
    builder.init();
}

#[tokio::main]
async fn main() {
    // 初始化日志
    init_log();
    if let Some(_) = get_pass_home() {
        let mut load_config = passcloud::load_config().expect("加载配置文件失败");

        let cli = passcloud::Cli::parse();

        let mut load_pass = passcloud::load_pass().expect("加载本地缓存失败");

        if let Some(command) = cli.command {
            match command {
                Commands::Config {
                    cloud_address,
                    username,
                    password,
                    config,
                    address,
                } => {
                    if let Some(config) = config {
                        // 如果指定了配置文件
                        load_config = Config::from_path(&config).expect("配置文件加载失败！");
                    } else {
                        // 否则使用部分配置的属性和默认的配置文件位置
                        let new_config =
                            Config::from_args(cloud_address, username, password, address);
                        handle::handle_pass_config_cli(&mut load_config, new_config);
                    }
                }
                Commands::Get { app, key, last } => {
                    handle::handle_get_cli(&load_pass, &load_config, app, key, last)
                }
                Commands::Set { app, key, password } => {
                    match handle::handle_set_cli(&mut load_pass, &load_config, &app, &key, password)
                    {
                        Ok(_) => {}
                        Err(e) => {
                            warn!("设置密码失败,reason:{}", e);
                        }
                    };
                }

                Commands::Gen { app, key, length } => {
                    let mut pass_length = 12;

                    if let Some(length) = length {
                        pass_length = length;
                    }
                    let pg = passcloud::get_password_generator(pass_length);

                    match pg.generate_one() {
                        Ok(password) => {
                            match handle::handle_set_cli(
                                &mut load_pass,
                                &load_config,
                                &app,
                                &key,
                                Some(password.clone()),
                            ) {
                                Ok(_) => {
                                    info!(
                                        "generate password: {} for key: {} in app:{}",
                                        password,
                                        key.unwrap(),
                                        app.unwrap()
                                    );
                                }
                                Err(e) => {
                                    warn!("generate password error,reason:{}", e)
                                }
                            };
                        }
                        Err(e) => {
                            warn!("generate password error,reason:{}", e)
                        }
                    }
                }
                Commands::Server { cmd } => match cmd {
                    ServerSubCmd::Start => {
                        handle::handle_start_cloud_server(&load_config).await;
                    }
                    ServerSubCmd::Stop => {
                        handle::handle_stop_cloud_server().await;
                    }
                },
                Commands::Client { cmd } => match cmd {
                    ClientSubCmd::Pull => match check_cloud_config(&load_config) {
                        Ok(_) => {
                            handle::handle_pull_pass(&load_config).await;
                        }
                        Err(e) => {
                            error!("检查配置出现错误,原因:{}", e);
                        }
                    },
                    ClientSubCmd::Push => match check_cloud_config(&load_config) {
                        Ok(_) => {
                            handle::handle_push_pass(&load_config, passcloud::load_pass().unwrap())
                                .await;
                        }
                        Err(e) => {
                            error!("检查配置出现错误,原因:{}", e);
                        }
                    },
                    ClientSubCmd::Register => {
                        handle::handle_register_pass(&load_config).await;
                    }
                    ClientSubCmd::Stop => {
                        handle::handle_stop_pass(&load_config).await;
                    }
                },
            }
        }
    } else {
        error!("请先配置PASS_HOME");
    }
}
