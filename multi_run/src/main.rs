use libc::openpty;
use std::{
    io::{self, Write},
    process::Command,
};

fn main() -> io::Result<()> {
    let command: Vec<_> = std::env::args_os().map(|i| i.as_os_str()).collect();
    let [_, command @ ..] = command.as_slice() else {
        return Err(io::Error::other("Invalid Arguments"));
    };
    if command.is_empty() {
        println!("no command to run");
        return Ok(());
    }

    let hosts = [
        "node_0.hattmo.com",
        "node_1.hattmo.com",
        "node_2.hattmo.com",
        "node_3.hattmo.com",
    ];

    let compiled: String = std::thread::scope(|t| {
        let mut results = Vec::new();
        for host in hosts {
            results.push((
                host,
                t.spawn::<_, Result<_, String>>(|| {
                    let mut out = Vec::new();
                    run_command(command, "root", host, &mut out).map_err(|e| e.to_string())?;
                    Ok(out)
                }),
            ));
        }
        results
            .into_iter()
            .map(|(host, result)| {
                let (Ok(v) | Err(v)) = result
                    .join()
                    .or(Err("Failed to join thread".to_owned()))
                    .flatten()
                    .map(|res| String::from_utf8_lossy(&res).into_owned());
                format!("---{host}---\n{v}\n")
            })
            .collect()
    });
    println!("{compiled}");
    Ok(())
}

fn run_command(
    command: &[&OsStr],
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
