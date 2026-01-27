#![allow(dead_code)]
#![allow(unused_imports)]

mod auth;
mod channels;
mod config;
mod credentials;
mod cron;
mod devices;
mod exec;
mod hooks;
mod logging;
mod media;
mod messages;
mod nodes;
mod plugins;
mod server;
mod sessions;

fn main() {
    println!("rusty-clawd gateway");
}
