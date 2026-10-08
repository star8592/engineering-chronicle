use std::io::{Read, Write};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h") {
        println!(
            "chronicle-cli canonicalize <文件>：验证受限 JSON 并输出规范字节。入账、签名与证据核验尚未实现。"
        );
        return Ok(());
    }
    if args.len() != 2 || args[0] != "canonicalize" {
        return Err("仅支持 --help 或 canonicalize <文件>".into());
    }
    let mut input = Vec::new();
    std::fs::File::open(&args[1])?
        .take((chronicle_protocol::json::MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut input)?;
    let canonical = chronicle_protocol::json::canonicalize(&input)?;
    std::io::stdout().lock().write_all(&canonical)?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
