fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h") {
        println!("chronicle-cli：工程初始化版本。事件入账与证据导出尚未实现。");
        return;
    }
    eprintln!("当前仅支持 --help；此程序尚不能入账、查询或导出证据。");
    std::process::exit(2);
}
