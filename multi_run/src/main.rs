use clap::Parser;
use libc::openpty;
use ratatui::{DefaultTerminal, Frame};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsStr,
    io::{self, Write},
    num::NonZero,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    thread::available_parallelism,
};

#[derive(Serialize, Deserialize)]
struct Host {
    host: String,
}

fn load_config() -> io::Result<Vec<Host>> {
    let home = std::env::var("HOME").map_err(io::Error::other)?;
    let config_path: PathBuf = format!("{home}/.config/multi_run").into();
    std::fs::create_dir_all(&config_path)?;
    let config_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .open(config_path.join(Path::new("hosts.yml")))?;

    let config: Vec<Host> = serde_saphyr::from_reader(config_file).map_err(io::Error::other)?;
    Ok(config)
}

#[derive(clap::Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    threads: Option<usize>,
    command: Vec<String>,
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();
    let command: &[String] = cli.command.as_slice();
    if command.is_empty() {
        println!("no command to run");
        return Ok(());
    }
    let config = load_config()?;
    let threads = cli
        .threads
        .or(available_parallelism().ok().map(NonZero::get))
        .unwrap_or(4);

    let joined_command = command.join(" ");
    println!(
        "Running command: {{{joined_command}}} on {{{}}} hosts with {{{threads}}} threads",
        config.len()
    );
    let (send, recv) = std::sync::mpsc::channel();
    config.into_iter().for_each(|h| {
        send.send(h).unwrap();
    });
    std::thread::scope(move |t| {
        let recv = Arc::new(Mutex::new(recv));
        for _ in 0..threads {
            let recv = recv.clone();
            t.spawn(move || {
                while let Ok(v) = recv.lock().unwrap().recv() {
                    let mut out = Vec::new();
                    run_command(command, "root", &v.host, &mut out).unwrap();
                    println!("{out:?}");
                }
            });
        }
    });
    Ok(())
}

fn app(terminal: &mut DefaultTerminal) -> io::Result<()> {
    loop {
        terminal.draw(render)?;
    }
}

fn render(frame: &mut Frame) {
    frame.render_widget("Hello", frame.area());
}

fn run_command(
    command: &[impl AsRef<OsStr>],
    user: &str,
    host: &str,
    mut out: impl Write,
) -> std::io::Result<()> {
    let mut amaster = 0;
    let amaster_ptr: *mut _ = &mut amaster;
    let mut aslave = 0;
    let aslave_ptr: *mut _ = &mut aslave;

    unsafe {
        openpty(
            amaster_ptr,
            aslave_ptr,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    let (mut pipe_read, pipe_write) = std::io::pipe()?;
    println!("Running command on {user}@{host}");
    let mut child = Command::new("ssh")
        .arg(format!("{user}@{host}"))
        .args(command)
        .stdout(pipe_write.try_clone()?)
        .stderr(pipe_write)
        .spawn()?;
    io::copy(&mut pipe_read, &mut out)?;
    child.wait()?;
    Ok(())
}

trait SpawnPty {
    fn spawn_pty();
}
