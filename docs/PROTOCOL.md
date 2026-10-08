# V0.1 协议实现进度

状态：EC-002第二小步，完整wire protocol与来源信任尚未冻结。

已实现：受限标识、字符串形式u64序号、声明的SHA-256摘要格式、来源位置和平台位置分离；受限JSON解析及规范编码；CLI canonicalize <文件>。

## 受限编码配置

根必须为对象；允许字符串、布尔、null、数组及对象；所有JSON数值token拒绝，数值字段必须使用规范字符串。原始输入上限1 MiB；根节点深度0，值边每下行一级加1，最大节点深度32。CLI最多读取上限+1字节。

重复字段按解码后的键判断，包含等价Unicode转义的重复键；嵌套重复键也拒绝。禁止非法UTF-8、孤立代理项、尾部多值。对象键按UTF-16 code unit排序；字符串按ECMAScript/JCS规则转义且不做Unicode正规化，数组顺序保留。输出精确字节无末尾换行。

这是RFC8785的无数值受限子集，不是完整JCS实现或完整Statement schema验证。未知关键字段拒绝、schema版本、签名、来源登记与授权尚未实现。M07部分完成，M08未完成。

## 验证

19项Rust测试；66个固定种子有效输入与独立Node编码器逐字节一致；CLI拒绝3个非法输入且stdout为空。Node JSON.parse不检验重复键，仅用于有效输入互操作。边界负例由Rust测试和CLI拒绝测试负责。

直接依赖固定serde 1.0.228与serde_json 1.0.151（MIT OR Apache-2.0），精确依赖树和checksum见Cargo.lock。参考：https://www.rfc-editor.org/rfc/rfc8785.html
