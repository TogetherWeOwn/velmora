//! Optional end-to-end client test over loopback; needs aws-cli and curl.
use super::{
    cors_rig, secret, through_front, Req, Rig, AKID, BUCKET, HOST, OBJECT, ORIGIN, REGION,
};
use std::process::{Command, Output};
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use velmora_bridge::{Method, UnixMs};

const AWS_CONFIG: &str = r#"{"CORSRules":[{"ID":"browser","AllowedOrigins":["https://app.example.test"],"AllowedMethods":["PUT"],"AllowedHeaders":["content-type","x-amz-*"],"ExposeHeaders":["ETag"],"MaxAgeSeconds":600}]}"#;

fn checked(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn clients(endpoint: &str, key: &str) {
    let url = format!("http://{HOST}");
    let bucket = &BUCKET[1..];
    let aws = |operation: &str, extra: &[&str]| {
        Command::new("aws")
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("AWS_ACCESS_KEY_ID", AKID)
            .env("AWS_SECRET_ACCESS_KEY", key)
            .env("AWS_CONFIG_FILE", "/dev/null")
            .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
            .env("AWS_EC2_METADATA_DISABLED", "true")
            .env("HTTP_PROXY", endpoint)
            .args([
                "--no-cli-pager",
                "--region",
                REGION,
                "--endpoint-url",
                &url,
                "s3api",
                operation,
                "--bucket",
                bucket,
            ])
            .args(extra)
            .output()
            .unwrap()
    };
    checked(aws(
        "put-bucket-cors",
        &["--cors-configuration", AWS_CONFIG],
    ));
    let got: serde_json::Value =
        serde_json::from_str(&checked(aws("get-bucket-cors", &[]))).unwrap();
    let expected: serde_json::Value = serde_json::from_str(AWS_CONFIG).unwrap();
    assert_eq!(got, expected);

    let preflight = || {
        checked(
            Command::new("curl")
                .args([
                    "--disable",
                    "--noproxy",
                    "",
                    "--proxy",
                    endpoint,
                    "--silent",
                    "--show-error",
                    "--max-time",
                    "10",
                    "--include",
                    "--request",
                    "OPTIONS",
                    "--header",
                    "Origin: https://app.example.test",
                    "--header",
                    "Access-Control-Request-Method: PUT",
                    "--header",
                    "Access-Control-Request-Headers: content-type,x-amz-date",
                    &format!("{url}{OBJECT}"),
                ])
                .output()
                .unwrap(),
        )
    };
    let ok = preflight();
    assert!(ok.starts_with("HTTP/1.1 200 "), "{ok}");
    assert!(
        ok.contains(&format!("access-control-allow-origin: {ORIGIN}\r\n")),
        "{ok}"
    );
    assert!(
        ok.contains("access-control-allow-headers: content-type, x-amz-date\r\n"),
        "{ok}"
    );
    assert!(ok.contains("access-control-max-age: 600\r\n"), "{ok}");
    checked(aws("delete-bucket-cors", &[]));
    let refused = preflight();
    assert!(refused.starts_with("HTTP/1.1 403 "), "{refused}");
    let missing = aws("get-bucket-cors", &[]);
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("NoSuchCORSConfiguration"));
}

// The service support `Req` is the only adapter here: the request target,
// headers and body are the bytes sent by the real clients to loopback.
async fn serve(rig: &Rig, mut stream: TcpStream) {
    let mut raw = Vec::new();
    let mut scratch = [0; 4096];
    let head = loop {
        let n = stream.read(&mut scratch).await.unwrap();
        assert_ne!(n, 0);
        raw.extend_from_slice(&scratch[..n]);
        assert!(raw.len() <= 64 * 1024);
        if let Some(at) = raw.windows(4).position(|b| b == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let mut lines = std::str::from_utf8(&raw[..head])
        .unwrap()
        .trim_end()
        .split("\r\n");
    let mut request_line = lines.next().unwrap().split(' ');
    let method = Method::parse(request_line.next().unwrap());
    let target = request_line
        .next()
        .unwrap()
        .strip_prefix(&format!("http://{HOST}"))
        .unwrap()
        .to_owned();
    let headers: Vec<_> = lines
        .map(|line| {
            let (name, value) = line.split_once(':').unwrap();
            (name.to_ascii_lowercase(), value.trim().to_owned())
        })
        .collect();
    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .map_or(0, |(_, value)| value.parse::<usize>().unwrap());
    assert!(length <= 64 * 1024);
    if headers
        .iter()
        .any(|(name, value)| name == "expect" && value == "100-continue")
    {
        stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .unwrap();
    }
    let mut body = raw.split_off(head);
    let already = body.len();
    assert!(already <= length);
    body.resize(length, 0);
    stream.read_exact(&mut body[already..]).await.unwrap();
    let request = Req {
        method,
        target,
        headers,
        body,
    }
    .into_request();
    let (response, _) = through_front(rig, request, false).await;
    let mut head = format!(
        "HTTP/1.1 {} Response\r\nconnection: close\r\ncontent-length: {}\r\n",
        response.status,
        response.body.len()
    );
    for (name, value) in response.headers {
        head += &format!("{name}: {value}\r\n");
    }
    head += "\r\n";
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&response.body).await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires the aws-cli and curl executables"]
async fn aws_cli_roundtrip_and_curl_preflight() {
    let mut rig = cors_rig();
    Rc::get_mut(&mut rig.bridge).unwrap().cfg.dev_trust_http = true;
    rig.bridge.clock.set(UnixMs(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64,
    ));
    rig.standard(&BUCKET[1..]).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let key = secret();
    let client = tokio::task::spawn_blocking(move || clients(&endpoint, key));
    let server = async {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            serve(&rig, stream).await;
        }
    };
    tokio::select! {
        result = client => result.unwrap(),
        () = server => unreachable!(),
        () = tokio::time::sleep(Duration::from_secs(60)) => panic!("loopback CORS clients timed out"),
    }
}
