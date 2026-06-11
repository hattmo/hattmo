mod byte_format;
mod cleanup;
mod setup;
mod web;

use std::{collections::VecDeque, fmt::Write, io::Result as IoResult};

use axum::serve::Listener;
use byte_format::ByteFormat;
use rand::distr::{Alphabetic, SampleString};
use setup::{GenericAddr, GenericStream, ServerSockets};
use time::{OffsetDateTime, macros::offset};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};

#[derive(Clone, Copy)]
enum Status {
    CheckingIn,
    Sleep,
    Upload,
    Download,
    Hostname,
    Netstat,
    ProcessList,
    Invoke,
    Shutdown,
    Done,
}

struct TestResult {
    time: OffsetDateTime,
    addr: GenericAddr,
    status: Status,
    log: String,
}

#[tokio::main]
async fn main() -> IoResult<()> {
    let ServerSockets {
        web,
        mut c2,
        is_activated,
    } = setup::setup_sockets().await?;
    let web_addr = web.local_addr()?;
    let c2_addr = c2.local_addr()?;
    println!("Started acme server");
    println!("Web address: {web_addr}");
    println!("C2 address: {c2_addr}");
    let results: &'static _ = Box::leak(Box::new(Mutex::new(VecDeque::new())));
    tokio::spawn(web::web_job(results, web, c2_addr));
    tokio::spawn(cleanup::cleanup_job(results, is_activated));
    loop {
        let (conn, addr) = c2.accept().await;
        println!("New rr connection from:{addr}");
        tokio::spawn(async move {
            let mut log = String::new();
            let status = match handle_connection(&mut log, conn).await {
                Ok(s) => s,
                Err((s, error)) => {
                    log += error.as_str();
                    s
                }
            };
            let time = time::UtcDateTime::now().to_offset(offset!(-4));
            let mut results = results.lock().await;
            results.push_back(TestResult {
                time,
                addr,
                status,
                log,
            });
            if results.len() > 40 {
                results.pop_front();
            }
        });
    }
}

const CHECKIN_MESSAGE: &[u8] = b"roadrunner checkin\0";
const SHUTDOWN_MESSAGE: &[u8] = b"shutting down\0";

async fn handle_connection(
    log: &mut String,
    mut conn: GenericStream,
) -> Result<Status, (Status, String)> {
    writeln!(log, "============\n").unwrap();
    writeln!(log, "Testing Checkin").unwrap();
    let mut status = Status::CheckingIn;
    handle_response(log, &mut conn, Some(CHECKIN_MESSAGE))
        .await
        .map_err(|msg| (status, msg))?;
    writeln!(log, "Checkin Successful").unwrap();
    writeln!(log, "============\n").unwrap();
    writeln!(log, "Testing Sleep Command").unwrap();
    status = Status::Sleep;
    send_recieve(log, &mut conn, b"sleep\0", b"1\0", None)
        .await
        .map_err(|msg| (status, msg))?;
    writeln!(log, "Sleep Command Successful").unwrap();
    writeln!(log, "============\n").unwrap();
    writeln!(log, "Testing Upload Command").unwrap();
    status = Status::Upload;
    let path_rnd = Alphabetic.sample_string(&mut rand::rng(), 16);
    let path = format!("/tmp/{path_rnd}.rr.txt\0").into_bytes();
    let content_rnd = Alphabetic.sample_string(&mut rand::rng(), 16);
    let content = format!("File from test server: {content_rnd}").into_bytes();
    let upload_arg = generate_upload_arg(&path, &content);
    send_recieve(log, &mut conn, b"upload\0", &upload_arg, None)
        .await
        .map_err(|msg| (status, msg))?;
    writeln!(log, "Upload Command Successful").unwrap();
    writeln!(log, "============\n").unwrap();
    writeln!(log, "Testing Download Command").unwrap();
    status = Status::Download;
    send_recieve(log, &mut conn, b"download\0", &path, Some(&content))
        .await
        .map_err(|msg| (status, msg))?;
    writeln!(log, "Download Command Successful").unwrap();
    writeln!(log, "============\n").unwrap();
    writeln!(log, "Testing Hostname Command").unwrap();
    status = Status::Hostname;
    send_recieve(log, &mut conn, b"hostname\0", b"\0", None)
        .await
        .map_err(|msg| (status, msg))?;
    writeln!(log, "Hostname Command Successful").unwrap();
    writeln!(log, "============\n").unwrap();
    writeln!(log, "Testing Netstat Command").unwrap();
    status = Status::Netstat;
    send_recieve(log, &mut conn, b"netstat\0", b"\0", None)
        .await
        .map_err(|msg| (status, msg))?;
    writeln!(log, "Netstat Command Successful").unwrap();
    writeln!(log, "============\n").unwrap();
    writeln!(log, "Testing Process List Command").unwrap();
    status = Status::ProcessList;
    send_recieve(log, &mut conn, b"proclist\0", b"\0", None)
        .await
        .map_err(|msg| (status, msg))?;
    writeln!(log, "Process List Command Successful").unwrap();
    writeln!(log, "============\n").unwrap();
    writeln!(log, "Testing Invoke Command").unwrap();
    status = Status::Invoke;
    send_recieve(log, &mut conn, b"invoke\0", b"ls -al\0", None)
        .await
        .map_err(|msg| (status, msg))?;
    writeln!(log, "Invoke Command Successful").unwrap();
    writeln!(log, "============\n").unwrap();
    writeln!(log, "Testing Shutdown Command").unwrap();
    status = Status::Shutdown;
    send_recieve(log, &mut conn, b"shutdown\0", b"\0", Some(SHUTDOWN_MESSAGE))
        .await
        .map_err(|msg| (status, msg))?;
    writeln!(log, "Shutdown Command Successful").unwrap();
    writeln!(log, "============\n").unwrap();
    status = Status::Done;
    Ok(status)
}

fn generate_upload_arg(path: &[u8], content: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let path_len = path.len() as u32;
    let content_len = content.len() as u32;
    out.extend(path_len.to_be_bytes());
    out.extend(path);
    out.extend(content_len.to_be_bytes());
    out.extend(content);
    out
}

async fn send_recieve(
    log: &mut String,
    conn: &mut GenericStream,
    command: &[u8],
    args: &[u8],
    expected: Option<&[u8]>,
) -> Result<(), String> {
    send_command(log, conn, command, args).await?;
    handle_response(log, conn, expected).await?;
    Ok(())
}

async fn send_command(
    log: &mut String,
    conn: &mut GenericStream,
    command: &[u8],
    args: &[u8],
) -> Result<(), String> {
    let cmd = generate_command(command, args);
    writeln!(log, "---Command---").unwrap();
    write!(log, "{:16.64}", ByteFormat(&cmd)).unwrap();
    writeln!(log, "-------------").unwrap();
    conn.write_all(&cmd)
        .await
        .map_err(|e| format!("Failed to send {} command: {e}", ByteFormat(command)))?;
    Ok(())
}

fn generate_command(command: &[u8], args: &[u8]) -> Vec<u8> {
    let command_len = command.len() as u32;
    let args_len = args.len() as u32;
    let total_len = command_len + args_len + 12;
    let mut out = Vec::new();
    out.extend(total_len.to_be_bytes());
    out.extend(command_len.to_be_bytes());
    out.extend(command);
    out.extend(args_len.to_be_bytes());
    out.extend(args);
    out
}

async fn handle_response(
    log: &mut String,
    conn: &mut GenericStream,
    expected_message: Option<&[u8]>,
) -> Result<(), String> {
    let body = parse_response(log, conn).await?;
    if let Some(expected) = expected_message
        && body != expected
    {
        return Err(format!(
            "Invalid response\nGot: {body:?}\nExpected: {expected:?}"
        ));
    }
    Ok(())
}

const MAX_MESSAGE_LEN: u32 = 20_000;

async fn parse_response(log: &mut String, conn: &mut GenericStream) -> Result<Vec<u8>, String> {
    let total_size = conn
        .read_u32()
        .await
        .map_err(|e| format!("Failed to read total size: {e}"))?;
    writeln!(log, "Total size: {total_size}").unwrap();
    let ret_code = conn
        .read_u32()
        .await
        .map_err(|e| format!("Failed to read return code: {e}"))?;
    writeln!(log, "Return code: {ret_code}").unwrap();
    let message_length = conn
        .read_u32()
        .await
        .map_err(|e| format!("Failed to read message length: {e}"))?;
    writeln!(log, "Message length: {message_length}").unwrap();
    if message_length > MAX_MESSAGE_LEN {
        return Err("Too much data in message".to_owned());
    }
    let message_length = message_length as usize;
    let mut body = vec![0u8; message_length];
    let res = conn
        .read_exact(&mut body)
        .await
        .map_err(|e| format!("Failed to read message body: {e}"))?;
    if res != message_length {
        return Err(format!(
            "Message body length does not match header: expected: {message_length}, actual: {res}"
        ));
    }
    writeln!(log, "---Response Body---").unwrap();
    write!(log, "{:16.64}", ByteFormat(&body)).unwrap();
    writeln!(log, "-------------------").unwrap();
    Ok(body)
}
