//! 把前端构建产物（`dist/`）内嵌进二进制（docs/WEBUI.md §7）。
//!
//! **为什么内嵌而不是从磁盘读**：这台机器的使用场景是"scp 一个二进制到服务器上"，
//! 旁边没有 `dist/` 目录。开发时用 `hiveproxy-cli run --web-assets <dir>` 从磁盘读，
//! 改完前端刷新浏览器即可，不必重编 Rust。
//!
//! 这里刻意不引入 `rust-embed` / `include_dir`（本机 crates.io 出口不稳，
//! 而且 core 一直保持依赖精简）。生成一张 `include_bytes!` 表就够了 —— 几十行纯 std。
//!
//! ★ **`dist/` 不存在不是错误**：那样会生成一张空表，运行时会返回一页
//! "此构建未内嵌界面"，而不是编译失败。构建顺序（先 bun run build 再 cargo）不该是硬性要求。

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    // crates/hiveproxy-core → 仓库根
    let dist = manifest.join("../../dist");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("assets.rs");

    println!("cargo:rerun-if-changed={}", dist.display());
    println!("cargo:rerun-if-changed=build.rs");

    let mut files = Vec::new();
    collect(&dist, &dist, &mut files);
    // 路径顺序稳定，免得没改任何东西也重编
    files.sort();

    let mut src = String::from(
        "// 由 build.rs 生成，请勿手改（内容来自 dist/）。\n\
         /// (URL 路径, 内容, Content-Type)\n\
         pub static ASSETS: &[(&str, &[u8], &str)] = &[\n",
    );
    for (url, abs) in &files {
        let _ = writeln!(
            src,
            "    ({:?}, include_bytes!({:?}), {:?}),",
            url,
            abs.to_string_lossy(),
            mime(url)
        );
    }
    src.push_str("];\n");

    if files.is_empty() {
        println!("cargo:warning=web 界面未内嵌：{} 不存在（先 `bun run build`）", dist.display());
    }

    std::fs::write(out, src).expect("写入 assets.rs 失败");
}

/// 递归收集 `dist/` 下的文件，URL 路径取相对 `dist/` 的那一段。
fn collect(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect(root, &p, out);
        } else if let Ok(rel) = p.strip_prefix(root) {
            // URL 一律用 `/` 分隔（Windows 上 strip_prefix 给的是 `\`）
            let url = format!("/{}", rel.to_string_lossy().replace('\\', "/"));
            out.push((url, p));
        }
    }
}

/// 一张够用的扩展名表。认不出来的一律 `application/octet-stream`
/// （宁可浏览器下载，也不要拿 `text/html` 去喂一个二进制 —— 那是 XSS 的老配方）。
fn mime(url: &str) -> &'static str {
    match url.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "txt" => "text/plain; charset=utf-8",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}