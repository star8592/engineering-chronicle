fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h") {
        println!("chronicle-verifier：工程初始化版本。离线核验尚未实现。");
        return;
    }
    eprintln!("当前仅支持 --help；此程序尚不能核验证据或判定发布资格。");
    std::process::exit(2);
}
