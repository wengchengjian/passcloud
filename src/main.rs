extern crate core;

use clap::Parser;
use passcloud;
use passcloud::{get_pass_home, handle, Commands, Config, Mode};

#[tokio::main]
async fn main() {
    if let Some(_) = get_pass_home() {
        let mut load_config = passcloud::load_config().expect("加载配置文件失败");

        match load_config.mode {
            Mode::Server => {}
            Mode::Client => {
                let cli = passcloud::Cli::parse();

                let mut load_pass = passcloud::load_pass().expect("加载本地缓存失败");

                match cli.command {
                    Commands::CONFIG {
                        offline,
                        debug,
                        cloud_address,
                        username,
                        password,
                        config,
                        run_mode,
                    } => {
                        if let Some(config) = config {
                            // 如果指定了配置文件
                            load_config = Config::from_path(&config).expect("配置文件加载失败！");
                        } else {
                            // 否则使用部分配置的属性和默认的配置文件位置
                            let new_config = Config::from_args(
                                offline,
                                debug,
                                cloud_address,
                                username,
                                password,
                                get_pass_mode(run_mode),
                            );
                            handle::handle_pass_config_cli(&mut load_config, new_config);
                        }
                    }
                    Commands::GET { app, key, list } => {
                        match handle::handle_get_cli(&load_pass, app, key, list) {
                            Err(e) => {
                                println!("Error: {}", e);
                            }
                            Ok(_) => {}
                        }
                    }
                    Commands::SET { app, key, password } => {
                        match handle::handle_set_cli(&mut load_pass, &app, &key, password) {
                            Ok(_) => {}
                            Err(e) => {
                                println!("设置密码失败,reason:{}", e);
                            }
                        };
                    }

                    Commands::PULL { all } => {
                        if !load_config.offline {
                            handle::handle_pull_pass(&load_config, &load_pass);
                        } else {
                            println!("离线模式无法拉取数据,请先设置offline为false,并配置服务端地址，用户名和密码");
                        }
                    }

                    Commands::PUSH { all } => {
                        if !load_config.offline {
                            handle::handle_push_pass(&load_config, &load_pass);
                        } else {
                            println!("离线模式无法推送数据,请先设置offline为false,并配置服务端地址，用户名和密码");
                        }
                    }

                    Commands::GEN { app, key, length } => {
                        let mut pass_length = 12;

                        if let Some(length) = length {
                            pass_length = length;
                        }
                        let pg = passcloud::get_password_generator(pass_length);

                        match pg.generate_one() {
                            Ok(password) => {
                                match handle::handle_set_cli(
                                    &mut load_pass,
                                    &app,
                                    &key,
                                    Some(password.clone()),
                                ) {
                                    Ok(_) => {
                                        println!(
                                            "generate password: {} for key: {} in app:{}",
                                            password,
                                            key.unwrap(),
                                            app.unwrap(),
                                        );
                                    }
                                    Err(e) => {
                                        println!("generate password error,reason:{}", e)
                                    }
                                };
                            }
                            Err(e) => {
                                println!("generate password error,reason:{}", e)
                            }
                        }
                    }
                }
            }
        }
    } else {
        println!("请先配置系统变量PASS_HOME");
    }
}

pub fn get_pass_mode(mode: Option<String>) -> Mode {
    if mode.or(Some(String::from("Client"))) == Some(String::from("Server")) {
        Mode::Server
    } else {
        Mode::Client
    }
}
