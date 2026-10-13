//! `http_proxy` 的单元测试。单独成文件的原因与 `stream_tests.rs` 相同：
//! 报文分帧的边界情况很多，和实现混在一个文件里会很难读。

use super::*;
fn req(method: &str, target: &str, headers: &[(&str, &str)]) -> ReqHead {
    ReqHead {
        method: method.into(),
        target: target.into(),
        version: 1,
        headers: headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// 目标解析
// ---------------------------------------------------------------------------

#[test]
fn absolute_uri_parses_into_host_port_and_origin_form() {
    let a = absolute_target("http://example.com/a/b?q=1").unwrap();
    assert!(matches!(&a.host, Host::Name(n) if n == "example.com"));
    assert_eq!(a.port, 80);
    assert_eq!(a.origin_form, "/a/b?q=1");

    // 只有主机名 → 根路径；只有查询串 → 补上 /
    assert_eq!(absolute_target("http://example.com").unwrap().origin_form, "/");
    assert_eq!(absolute_target("http://example.com?q=1").unwrap().origin_form, "/?q=1");

    // 显式端口
    let a = absolute_target("http://example.com:8080/x").unwrap();
    assert_eq!(a.port, 8080);
    assert_eq!(authority_of(&Endpoint::new(a.host, a.port), a.default_port), "example.com:8080");

    // IPv6 字面量
    let a = absolute_target("http://[fd00::9]:9000/x").unwrap();
    assert!(matches!(a.host, Host::Ip(std::net::IpAddr::V6(_))));
    assert_eq!(a.port, 9000);
}

#[test]
fn absolute_uri_rejects_what_a_forward_proxy_cannot_do() {
    // https 必须走 CONNECT
    assert!(absolute_target("https://example.com/").unwrap_err().contains("CONNECT"));
    // origin-form：客户端把代理当源站了 —— 错误信息必须说清这件事
    let why = absolute_target("/index.html").unwrap_err();
    assert!(why.contains("代理端口"), "{why}");
    assert!(why.contains("绝对 URI"), "{why}");
    // CONNECT 的目标形式
    assert!(absolute_target("example.com:443").is_err());
}

#[test]
fn userinfo_is_stripped_so_credentials_never_reach_the_origin() {
    let a = absolute_target("http://user:pass@example.com/x").unwrap();
    assert!(matches!(&a.host, Host::Name(n) if n == "example.com"));
}

#[test]
fn authority_parsing_handles_brackets_and_required_ports() {
    // CONNECT 必须带端口（default_port = 0）
    assert!(parse_host_port("example.com", 0).is_none());
    assert!(parse_host_port("example.com:443", 0).is_some());
    // 未加方括号的 IPv6 只能拒绝，不能猜
    assert!(parse_host_port("fd00::9:443", 0).is_none());
    let (h, p) = parse_host_port("[fd00::9]:443", 0).unwrap();
    assert!(matches!(h, Host::Ip(std::net::IpAddr::V6(_))));
    assert_eq!(p, 443);
    // 域名大小写与端口缺省
    let (h, p) = parse_host_port("Example.COM", 80).unwrap();
    assert!(matches!(h, Host::Name(n) if n == "Example.COM"));
    assert_eq!(p, 80);
}

// ---------------------------------------------------------------------------
// 报文解析
// ---------------------------------------------------------------------------

#[tokio::test]
async fn request_head_can_arrive_in_pieces() {
    let (mut io, mut w) = tokio::io::duplex(4096);
    let mut buf = BytesMut::new();

    w.write_all(b"GET http://a.example/x HTTP/1.1\r\nHost: a.example\r\n").await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), read_request_head(&mut io, &mut buf))
            .await
            .is_err(),
        "头部没结束时不该返回"
    );

    w.write_all(b"\r\n").await.unwrap();
    let head = read_request_head(&mut io, &mut buf).await.unwrap().unwrap();
    assert_eq!(head.method, "GET");
    assert_eq!(head.target, "http://a.example/x");
    assert_eq!(head.version, 1);
    assert_eq!(header(&head.headers, "host"), Some("a.example"));
}

#[tokio::test]
async fn request_head_leaves_the_body_in_the_buffer() {
    let (mut io, mut w) = tokio::io::duplex(4096);
    let mut buf = BytesMut::new();
    w.write_all(b"POST http://a.example/x HTTP/1.1\r\ncontent-length: 5\r\n\r\nhelloNEXT")
        .await
        .unwrap();
    let head = read_request_head(&mut io, &mut buf).await.unwrap().unwrap();
    assert_eq!(request_body(&head).unwrap(), Body::Length(5));
    assert_eq!(&buf[..], b"helloNEXT", "头部之后的字节必须留在缓冲里给请求体用");
}

#[tokio::test]
async fn clean_eof_between_requests_ends_the_loop() {
    let (mut io, w) = tokio::io::duplex(4096);
    let mut buf = BytesMut::new();
    drop(w);
    assert!(read_request_head(&mut io, &mut buf).await.unwrap().is_none());
}

#[test]
fn response_head_parsing_uses_httparse() {
    let raw = b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nx-a: b\r\n\r\n";
    let mut headers = [EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut headers);
    assert!(matches!(resp.parse(raw), Ok(Status::Complete(_))));
    assert_eq!(resp.code, Some(404));
    assert_eq!(resp.reason, Some("Not Found"));
}

// ---------------------------------------------------------------------------
// 分帧
// ---------------------------------------------------------------------------

#[test]
fn request_body_framing_is_validated() {
    assert_eq!(request_body(&req("GET", "/x", &[])).unwrap(), Body::None);
    assert_eq!(
        request_body(&req("POST", "/x", &[("content-length", "12")])).unwrap(),
        Body::Length(12)
    );
    assert_eq!(
        request_body(&req("POST", "/x", &[("content-length", "0")])).unwrap(),
        Body::None
    );
    assert_eq!(
        request_body(&req("POST", "/x", &[("transfer-encoding", "chunked")])).unwrap(),
        Body::Chunked
    );

    // ★ 防请求走私：分帧矛盾一律拒绝，绝不"挑一个转发"
    let both = req("POST", "/x", &[("content-length", "5"), ("transfer-encoding", "chunked")]);
    assert!(request_body(&both).unwrap_err().contains("走私"));
    let conflicting = req("POST", "/x", &[("content-length", "5"), ("content-length", "6")]);
    assert!(request_body(&conflicting).is_err());
    let not_a_number = req("POST", "/x", &[("content-length", "5x")]);
    assert!(request_body(&not_a_number).is_err());
    let gzip = req("POST", "/x", &[("transfer-encoding", "gzip")]);
    assert!(request_body(&gzip).is_err());
}

#[test]
fn response_body_framing_covers_the_awkward_statuses() {
    let mk = |status: u16, headers: &[(&str, &str)]| RespHead {
        status,
        reason: String::new(),
        version: 1,
        headers: headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect(),
        raw: Bytes::new(),
    };

    assert_eq!(response_body(&mk(204, &[("content-length", "9")]), "GET"), RespBody::None);
    assert_eq!(response_body(&mk(304, &[]), "GET"), RespBody::None);
    // HEAD 的响应该有长度但**没有正文**
    assert_eq!(response_body(&mk(200, &[("content-length", "9")]), "HEAD"), RespBody::None);
    assert_eq!(response_body(&mk(200, &[("content-length", "9")]), "GET"), RespBody::Length(9));
    assert_eq!(
        response_body(&mk(200, &[("transfer-encoding", "chunked")]), "GET"),
        RespBody::Chunked
    );
    // 既没长度也没 chunked → 只能读到连接结束（这条上游不可复用）
    assert_eq!(response_body(&mk(200, &[]), "GET"), RespBody::UntilEof);
}

#[test]
fn chunk_size_lines_accept_extensions() {
    assert_eq!(parse_chunk_size(b"1a\r\n"), Some(26));
    assert_eq!(parse_chunk_size(b"0\r\n"), Some(0));
    assert_eq!(parse_chunk_size(b"5;name=value\r\n"), Some(5));
    assert_eq!(parse_chunk_size(b"zz\r\n"), None);
    assert_eq!(parse_chunk_size(b"\r\n"), None);
}

// ---------------------------------------------------------------------------
// 头部改写
// ---------------------------------------------------------------------------

#[test]
fn request_head_is_rewritten_to_origin_form() {
    let head = req(
        "GET",
        "http://a.example/x",
        &[
            ("Host", "a.example"),
            ("Proxy-Connection", "Keep-Alive"),
            ("Proxy-Authorization", "Basic c2VjcmV0"),
            ("Expect", "100-continue"),
            ("Accept", "*/*"),
        ],
    );
    let out = String::from_utf8(rewrite_request_head(&head, "/x", "a.example")).unwrap();
    assert!(out.starts_with("GET /x HTTP/1.1\r\n"), "{out}");
    assert!(out.contains("Host: a.example\r\n"), "{out}");
    assert!(out.contains("Accept: */*\r\n"), "{out}");
    assert!(!out.to_ascii_lowercase().contains("proxy-"), "代理专用头不得转发：{out}");
    assert!(!out.to_ascii_lowercase().contains("expect"), "Expect 由本地代答：{out}");
    assert!(out.ends_with("\r\n\r\n"), "{out}");
}

#[test]
fn missing_host_is_supplied() {
    let head = req("GET", "http://a.example/x", &[("Accept", "*/*")]);
    let out = String::from_utf8(rewrite_request_head(&head, "/x", "a.example")).unwrap();
    assert!(out.contains("Host: a.example\r\n"), "{out}");
}

#[test]
fn response_head_gets_our_own_connection_header() {
    let resp = RespHead {
        status: 200,
        reason: "OK".into(),
        version: 1,
        headers: [
            ("Content-Length", "3"),
            ("Connection", "keep-alive"),
            ("Keep-Alive", "timeout=5"),
            ("Proxy-Authenticate", "Basic"),
            ("Server", "nginx"),
        ]
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect(),
        raw: Bytes::new(),
    };
    let out = String::from_utf8(rebuild_response_head(&resp, "close")).unwrap();
    assert!(out.starts_with("HTTP/1.1 200 OK\r\n"), "{out}");
    assert!(out.contains("Content-Length: 3\r\n"), "分帧头必须保留：{out}");
    assert!(out.contains("Server: nginx\r\n"), "{out}");
    assert!(out.contains("Connection: close\r\n"), "{out}");
    assert!(!out.contains("keep-alive"), "逐跳头由我们重写：{out}");
    assert!(!out.to_ascii_lowercase().contains("proxy-"), "{out}");
}

// ---------------------------------------------------------------------------
// 保持连接
// ---------------------------------------------------------------------------

#[test]
fn keepalive_intent_follows_http_version_rules() {
    let mut h = req("GET", "/x", &[]);
    assert!(client_wants_keepalive(&h), "1.1 默认 keep-alive");
    h.headers.push(("Connection".into(), "close".into()));
    assert!(!client_wants_keepalive(&h));

    let mut h10 = req("GET", "/x", &[]);
    h10.version = 0;
    assert!(!client_wants_keepalive(&h10), "1.0 默认关连接");
    h10.headers.push(("Connection".into(), "Keep-Alive".into()));
    assert!(client_wants_keepalive(&h10));

    // 响应侧：
    let close = vec![("Connection".to_string(), "close".to_string())];
    assert!(says_close(&close));
    assert!(!says_close(&[("Connection".to_string(), "keep-alive".to_string())]));
    assert!(!says_close(&[]));
}

#[test]
fn continue_expectation_is_detected_locally() {
    assert!(wants_continue(&req("POST", "/x", &[("Expect", "100-continue")])));
    assert!(!wants_continue(&req("POST", "/x", &[])));
}

// ---------------------------------------------------------------------------
// 字节搬运
// ---------------------------------------------------------------------------

#[tokio::test]
async fn chunked_body_is_relayed_verbatim_and_ends_exactly_at_the_terminator() {
    let (mut src, mut feed) = tokio::io::duplex(4096);
    let (mut out, sink) = tokio::io::duplex(4096);
    let raw = b"5\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\nNEXT";
    feed.write_all(raw).await.unwrap();

    let mut buf = BytesMut::new();
    copy_chunked(&mut src, &mut buf, &mut out).await.unwrap();
    assert_eq!(&buf[..], b"NEXT", "终止块之后的字节必须留在缓冲里（下一个请求的起点）");

    drop(out);
    let mut got = Vec::new();
    use tokio::io::AsyncReadExt as _;
    let mut sink = sink;
    sink.read_to_end(&mut got).await.unwrap();
    assert_eq!(
        got,
        b"5\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\n".to_vec(),
        "chunked 体必须逐字节原样透传（含 trailer）"
    );
}

#[tokio::test]
async fn chunked_body_cut_in_the_middle_is_an_error_not_silent_truncation() {
    let (mut src, mut feed) = tokio::io::duplex(4096);
    let (mut out, _sink) = tokio::io::duplex(4096);
    feed.write_all(b"5\r\nhel").await.unwrap();
    drop(feed);
    let mut buf = BytesMut::new();
    let err = copy_chunked(&mut src, &mut buf, &mut out).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn copy_exact_moves_the_declared_number_of_bytes() {
    let (mut src, mut feed) = tokio::io::duplex(4096);
    let (mut out, sink) = tokio::io::duplex(4096);
    feed.write_all(b"0123456789TAIL").await.unwrap();
    drop(feed);
    let mut buf = BytesMut::new();
    copy_exact(&mut src, &mut buf, 10, &mut out).await.unwrap();
    assert_eq!(&buf[..], b"TAIL");
    drop(out);
    let mut got = Vec::new();
    use tokio::io::AsyncReadExt as _;
    let mut sink = sink;
    sink.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"0123456789");
}

#[tokio::test]
async fn copy_until_eof_drains_everything() {
    let (mut src, mut feed) = tokio::io::duplex(4096);
    let (mut out, sink) = tokio::io::duplex(4096);
    feed.write_all(b"no length header here").await.unwrap();
    drop(feed);
    let mut buf = BytesMut::new();
    copy_until_eof(&mut src, &mut buf, &mut out).await.unwrap();
    drop(out);
    let mut got = Vec::new();
    use tokio::io::AsyncReadExt as _;
    let mut sink = sink;
    sink.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"no length header here");
}

// ---------------------------------------------------------------------------
// 错误应答
// ---------------------------------------------------------------------------

#[tokio::test]
async fn error_replies_are_well_framed_and_say_something_useful() {
    let (mut server, mut client) = tokio::io::duplex(4096);
    reply_error(&mut server, 403, "被本地规则拒绝").await.unwrap();
    drop(server);
    let mut got = Vec::new();
    use tokio::io::AsyncReadExt as _;
    client.read_to_end(&mut got).await.unwrap();
    let text = String::from_utf8(got).unwrap();
    assert!(text.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{text}");
    assert!(text.contains("content-length: "), "{text}");
    assert!(text.contains("connection: close\r\n"), "{text}");
    assert!(text.ends_with("被本地规则拒绝\n"), "正文要有中文说明：{text}");
}