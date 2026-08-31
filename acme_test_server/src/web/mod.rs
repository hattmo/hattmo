use crate::setup::{GenericAddr, GenericListener};

use super::{Status, TestResult};

use std::{collections::VecDeque, io::Result as IoResult};

use axum::{
    extract::State,
    response::{Html, IntoResponse},
    routing::get,
};
use time::macros::format_description;
use tokio::sync::Mutex;

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

pub async fn web_job(
    results: &'static Mutex<VecDeque<TestResult>>,
    listener: GenericListener,
    c2_addr: GenericAddr,
) -> IoResult<()> {
    let port: &'static str = c2_addr
        .to_string()
        .split_once(":")
        .map(|(_, p)| format!("<h3>C2 Port: {p}</h3>").leak() as &'static str)
        .map(|i| i)
        .unwrap_or("");
    let router = axum::Router::new()
        .route("/", get(root))
        .with_state((results, port));
    axum::serve(listener, router).await?;
    Ok(())
}

static TABLE_HEAD: &str = r##"
<table>
    <tr>
        <th>Time</th>
        <th>IP</th>
        <th>CheckingIn</th>
        <th>Sleep</th>
        <th>Upload</th>
        <th>Download</th>
        <th>Hostname</th>
        <th>Netstat</th>
        <th>ProcessList</th>
        <th>Invoke</th>
        <th>Shutdown</th>
        <th>Done</th>
        <th>Logs</th>
    </tr>
"##;

static TABLE_TAIL: &str = r##"
</table>
"##;

async fn root(
    State((state, c2_port)): State<(&'static Mutex<VecDeque<TestResult>>, &'static str)>,
) -> impl IntoResponse {
    let rows: String = state
        .lock()
        .await
        .iter()
        .rev()
        .enumerate()
        .map(
            |(
                i,
                TestResult {
                    time,
                    addr,
                    status,
                    log,
                },
            )| {
                let mut marks = [' '; 10];
                let n = match status {
                    Status::CheckingIn => 0,
                    Status::Sleep => 1,
                    Status::Upload => 2,
                    Status::Download => 3,
                    Status::Hostname => 4,
                    Status::Netstat => 5,
                    Status::ProcessList => 6,
                    Status::Invoke => 7,
                    Status::Shutdown => 8,
                    Status::Done => 9,
                };
                marks[..n].fill('\u{2705}');
                marks[n] = '\u{274C}';
                if let Status::Done = status {
                    marks[n] = '\u{2705}';
                }
                let marks: String = marks.into_iter().map(|c| format!("<td>{c}</td>")).collect();
                let time = time
                    .format(format_description!("[hour]:[minute]"))
                    .unwrap_or_else(|_| "00:00".to_string());
                let escaped_addr = escape_html(&addr.to_string());
                let escaped_log = escape_html(log);
                let tds = format!("<td>{time}</td><td>{escaped_addr}</td>") + &marks;
                format!(
                    "<tr>{tds}<td><a href=\"#{i}\">\u{2795}</a><a href=\"#\">\u{2796}</a></td></tr>
                    <tr id=\"{i}\" class=\"expandable\"><td colspan=13><pre>{escaped_log}</pre></td></tr>"
                )
            },
        )
        .collect();

    let escaped_c2_port = escape_html(c2_port);
    Html(format!(
        "<html>
            <head>
                <style>
table, th, td {{
    border: 1px solid black;
}}
.expandable {{
    display: none;
}}
.expandable:target {{
    display: block;
}}
a {{
    all: unset;
    cursor: pointer;
}}
                </style>
            </head>
            <body>
                <h1>ACME TEST SERVER</h1>
                {escaped_c2_port}
                {TABLE_HEAD}
                {rows}
                {TABLE_TAIL}
            </body>
        </html>"
    ))
}
