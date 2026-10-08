use std::io::{Read, Write};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h") {
        println!(
            "chronicle-cli canonicalize <文件>：受限 JSON 编码；validate-header <文件>：严格 header 校验并输出规范字节。envelope-pae <文件>：解析封套并输出待签字节。均不核验身份、授权或签名。"
        );
        return Ok(());
    }
    if args.len() != 2
        || !matches!(
            args[0].as_str(),
            "canonicalize" | "validate-header" | "envelope-pae"
        )
    {
        return Err(
            "仅支持 --help、canonicalize <文件> 、validate-header <文件> 或 envelope-pae <文件>"
                .into(),
        );
    }
    let mut input = Vec::new();
    std::fs::File::open(&args[1])?
        .take((chronicle_protocol::json::MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut input)?;
    let canonical = if args[0] == "envelope-pae" {
        chronicle_protocol::envelope::HeaderEnvelopeCandidate::parse(&input)?.signing_bytes()?
    } else if args[0] == "validate-header" {
        chronicle_protocol::header::HeaderCandidate::parse(&input)?
            .canonical_bytes()
            .to_vec()
    } else {
        chronicle_protocol::json::canonicalize(&input)?
    };
    std::io::stdout().lock().write_all(&canonical)?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
