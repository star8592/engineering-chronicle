# V0.1 协议实现进度

状态：EC-002第五小步，完整wire protocol与来源信任尚未冻结。

已实现：受限标识、字符串形式u64序号、声明的SHA-256摘要格式、来源位置和平台位置分离；受限JSON解析及规范编码；实验性版本化 header candidate；CLI canonicalize / validate-header <文件>。

## 受限编码配置

根必须为对象；允许字符串、布尔、null、数组及对象；所有JSON数值token拒绝，数值字段必须使用规范字符串。原始输入上限1 MiB；根节点深度0，值边每下行一级加1，最大节点深度32。CLI最多读取上限+1字节。

重复字段按解码后的键判断，包含等价Unicode转义的重复键；嵌套重复键也拒绝。禁止非法UTF-8、孤立代理项、尾部多值。对象键按UTF-16 code unit排序；字符串按ECMAScript/JCS规则转义且不做Unicode正规化，数组顺序保留。输出精确字节无末尾换行。

这是RFC8785的无数值受限子集，不是完整JCS实现或完整Statement envelope验证。Header candidate已拒绝未知字段并检查schema版本；签名、完整Statement载荷、来源登记与授权尚未实现。M07部分完成，M08未完成。

## 验证

44项Rust测试；66个固定种子有效输入与独立Node编码器逐字节一致；编码CLI拒绝3个非法输入；header CLI接受1个有效输入并拒绝8个非法输入，所有拒绝均stdout为空。Node JSON.parse不检验重复键，仅用于有效输入互操作。边界负例由Rust测试和CLI拒绝测试负责。

直接依赖固定serde 1.0.228与serde_json 1.0.151（MIT OR Apache-2.0），精确依赖树和checksum见Cargo.lock。参考：https://www.rfc-editor.org/rfc/rfc8785.html

## 实验性 Statement header candidate

schema 精确值为 `ec.statement-header.v0.1`。根对象仅允许并要求 schema、project、position、kind、subject；position 仅允许并要求 source、epoch、sequence。除 position 为对象外，所有字段必须为字符串，不做类型转换。project/source/epoch/kind 使用已有 Identifier 规则；sequence 使用 Counter；subject 使用声明摘要格式。未知字段（包含 signature、receipt、authorized 与 extensions）拒绝，防止把额外字段误认为已经验证。

示例（摘要仅为格式示例，不宣称存在对应资产）：

```json
{"schema":"ec.statement-header.v0.1","project":"p1","position":{"source":"ci1","epoch":"e1","sequence":"0"},"kind":"test.failed","subject":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
```

`HeaderCandidate::parse` 先执行受限编码检查，再构建严格结构；重复键不会被通用JSON map静默覆盖。类型保持不可变，公开只读header与精确规范字节。CLI `validate-header <文件>` 成功时仅输出该header的规范字节，失败退出2且不输出stdout。名称与输出均不代表授权或可信状态。

这是独立header草案，尚不是完整Statement envelope或签名输入规范；字段中的来源和摘要仍是调用者的声明。后续完整封套与签名域需另行版本化。M07仍部分完成，M08仍未完成。

## 实验性 header envelope

新增不可变 HeaderEnvelopeCandidate、SignatureCandidate 与 DSSE v1 PAE 编码。CLI `envelope-pae <文件>` 输出精确待签字节；不执行签名核验。载荷必须是上述header的规范字节，payloadType固定；未知字段、非法Base64、非规范载荷与错误长度拒绝。完整字段、限制和兼容差异见 [ADR-0003](adr/ADR-0003.md)。

新增base64精确依赖0.22.1（MIT OR Apache-2.0）；锁文件更新。4个CLI编码变体与独立Python PAE逐字节一致，6个非法封套拒绝且stdout为空。Rust包含DSSE官方PAE向量。此结果不证明Ed25519验签正确或来源获授权。

## 签名匹配诊断

新增 `verify_ed25519` 与 `HeaderEnvelopeCandidate::match_signature`。精确固定 ed25519-dalek 2.2.0，禁用默认feature，仅启用std，未启用legacy_compatibility、batch、hazmat或随机密钥生成。使用Pure Ed25519和verify_strict；显式拒绝低阶弱公钥。from_bytes采用库的ZIP-215点解码规则；此组合不声称实现完整RFC8032点接受规则。

`CryptographicMatch`只绑定不可变封套、公钥字节和签名索引，不产生可信/授权标志。keyid不参与匹配，不能凭包内提示选择信任根。

CLI `match-signature <封套文件> <公钥文件>` 读取外部精确32字节原始Ed25519公钥；最多读取33字节以拒绝超长文件。任一签名候选与该公钥匹配时输出 `SIGNATURE_MATCH_ONLY` 并退出0，否则退出2且stdout为空。此为单钥诊断，不支持授权政策、身份归属或多签门限。

44项Rust测试包含RFC8032 §7.1前三个向量、64个逐字节签名篡改、弱钥/低阶R/非规范S、错误公钥、修改载荷及签原始载荷而非PAE的拒绝。已修正首次录入的第三个RFC向量错误。独立Python cryptography 46.0.5生成的固定签名fixture用于Rust及CLI交叉检查；CI执行fixture只需Python标准库，不依赖cryptography。CLI两个匹配用例及六个拒绝用例通过。

来源登记、project/source/epoch/kind授权、撤销/轮换、完整Statement、Receipt和资产哈希仍未实现；M07部分完成、M08未完成。签名匹配不能证明subject资产存在或陈述真实。
参考：https://docs.rs/ed25519-dalek/2.2.0/ed25519_dalek/struct.VerifyingKey.html
