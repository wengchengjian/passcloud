extern crate core;

use clap::Parser;
use passcloud;
use passcloud::{get_pass_home, handle, Commands, Config};
use std::process;

fn main() {
    if let Some(path) = get_pass_home() {
        let cli = passcloud::Cli::parse();

        let mut load_config = passcloud::load_config().expect("加载配置文件失败");

        let mut load_pass = passcloud::load_pass().expect("加载本地缓存失败");

        if let Some(command) = cli.command {
            match command {
                Commands::CONFIG {
                    offline,
                    debug,
                    cloud_address,
                    username,
                    password,
                    config,
                } => {
                    if let Some(config) = config {
                        // 如果指定了配置文件
                        load_config = Config::from_path(&config).expect("配置文件加载失败！");
                    } else {
                        // 否则使用部分配置的属性和默认的配置文件位置
                        let new_config =
                            Config::from_args(offline, debug, cloud_address, username, password);
                        handle::handle_pass_config_cli(&mut load_config, new_config);
                    }
                }
                Commands::GET { app, key, last } => {
                    handle::handle_get_cli(&load_pass, app, key, last)
                }
                Commands::SET { app, key, password } => {
                    match handle::handle_set_cli(&mut load_pass, &app, &key, password) {
                        Ok(_) => {}
                        Err(e) => {
                            println!("设置密码失败,reason:{}", e);
                        }
                    };
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
        } else {
            println!("Command not found");
        }
    } else {
        println!("请先配置PASS_HOME");
    }
}
