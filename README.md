# Engineering Chronicle

可验证的软件工程陈述、交付证据与历史基础设施。

## 当前状态

这是 EC-001 工程初始化版本。四个 Rust crate 可以构建，CLI 只提供项目状态说明；尚未实现账本、签名、证据核验、数据库、发布门禁或工程重演。基础 CI 通过也不代表 M01–M14 产品验收通过。

## 首个产品闭环

真实 Rust 变更：测试失败 → 修复 → 复测 → 交付证据包 → 离线核验。

协议、基础内核、SDK/适配器和离线验证器采用 Apache-2.0。托管、组织治理、企业集成及支持是商业方向，尚未提供商业服务。

## 本地检查

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo doc --workspace --no-deps --locked
cargo run --locked -p chronicle-cli -- --help
cargo run --locked -p chronicle-verifier -- --help
```

## 历史与边界

- [创世档案](docs/genesis/GENESIS-0000.md)
- [GPT-6.1 独立评审](docs/genesis/GENESIS-REVIEW-0001.md)
- [首版架构决策](docs/adr/ADR-0001.md)
- [开源与商业路线](docs/adr/ADR-0002.md)
- [里程碑](docs/MILESTONES.md)

历史档案记录思想与建议，不能替代运行证据。签名和完整性证明不保证陈述真实或软件绝对正确。
