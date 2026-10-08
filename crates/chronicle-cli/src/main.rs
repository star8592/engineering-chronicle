use std::io::{Read, Write};

fn read_bounded(path: &str, max: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take((max + 1) as u64)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h") {
        println!(
            "chronicle-cli canonicalize <文件>：受限 JSON 编码；validate-header <文件>：header 校验；envelope-pae <文件>：待签字节；match-signature <封套文件> <32字节公钥文件>：仅匹配签名。所有命令均不核验来源授权或证据真实性。"
        );
        return Ok(());
    }
    let encoding = args.len() == 2
        && matches!(
            args[0].as_str(),
            "canonicalize" | "validate-header" | "envelope-pae"
        );
    let matching = args.len() == 3 && args[0] == "match-signature";
    if !encoding && !matching {
        return Err("用法请查看 --help".into());
    }
    let input = read_bounded(&args[1], chronicle_protocol::json::MAX_INPUT_BYTES)?;
    let output = if matching {
        let key: [u8; 32] = read_bounded(&args[2], 32)?
            .try_into()
            .map_err(|_| "公钥文件必须为精确32字节原始Ed25519公钥")?;
        let candidate = chronicle_protocol::envelope::HeaderEnvelopeCandidate::parse(&input)?;
        // No keyid filtering or self-declared trust; one matching signature suffices
        // only for this diagnostic command, not for any authorization policy.
        let matched = (0..candidate.signatures().len())
            .any(|index| candidate.match_signature(index, &key).is_ok());
        if !matched {
            return Err("签名不匹配；不能据此推断来源授权".into());
        }
        b"SIGNATURE_MATCH_ONLY\n".to_vec()
    } else if args[0] == "envelope-pae" {
        chronicle_protocol::envelope::HeaderEnvelopeCandidate::parse(&input)?.signing_bytes()?
    } else if args[0] == "validate-header" {
        chronicle_protocol::header::HeaderCandidate::parse(&input)?
            .canonical_bytes()
            .to_vec()
    } else {
        chronicle_protocol::json::canonicalize(&input)?
    };
    std::io::stdout().lock().write_all(&output)?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
