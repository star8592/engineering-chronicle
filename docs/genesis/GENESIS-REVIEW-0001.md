# Engineering Chronicle Genesis Independent Architecture Review — GPT-6.1

> 记录编号：GENESIS-REVIEW-0001  
> 状态：**独立评审建议，尚未裁决／实现**  
> 评审日期：2026-10-08 UTC（Asia/Shanghai 为 2026-10-09）  
> 评审输入：通过 Library read 完整读取 GENESIS-0000.md，386 行，返回 has_more=false。  
> 评审角色：独立首席架构评审者；本报告不修改创世档案、不宣称产品实现。  
> 模型选择：本次代理工具调用选择 **gpt-6.1-sol**。这是会话执行配置的记录，**不是密码学模型身份认证**，亦不证明任何输出正确。  
> 证据分类：**[事实]** 为本轮查阅的一手文档支持的技术事实；**[假设]** 为待实测或待批准的工程选择；**[研究]** 为尚无本项目证据的构想。

## 1. 评审结论

愿景成立，但应把首版定义为“可验证的工程陈述与交付证据账本”，暂不定义为完整工程世界模型。项目最危险的失败不是漏画一个节点，而是给不完整、来源受污染的历史出具可信外观。

建议以“真实 Rust 项目一次失败→修复→复测→导出护照→离线核验”为首个闭环。三内核保留为愿景边界，不在首版分别建设三套引擎。纯签名与 Merkle 根不能替代外部固定检查点、来源核对和运行隔离。

## 2. 对 Genesis 的主要异议

| 编号 | 对应原文 | 异议与修订建议 |
|---|---|---|
| REV-01 | §3 六对象、§4 三内核 | 六对象混合来源陈述、派生状态、治理政策与执行计划。保留领域词汇；协议先区分来源 Statement、平台 Receipt、验证 Assessment，避免把所有对象强行放进一种 Event。 |
| REV-02 | §5 L1–L3、§10 V0.1 | 无外部已知检查点，攻击者可提供合法旧前缀或重签整段历史。外部固定检查点应进入 MVP 验收；独立见证服务可随后建设。 |
| REV-03 | §8 全程回放、§11 完整日志 | 被接收的陈述未被修改，不证明现实事件全部被采集。协议必须声明采集范围、来源游标、缺口与核对结果，禁止“日志验证通过＝工程历史完整”。 |
| REV-04 | §3.1 概念 Schema | 来源不能签署尚未分配的 committed_sequence；signature_ref、event_id 与内容摘要可能产生自引用。来源内容与平台接收信息必须分别编码、分别签署。 |
| REV-05 | §3 VERIFIED、§7 门禁 | VERIFIED 不能成为来源自行设置的身份属性。验证结论必须指向精确对象、规则、环境、执行器、覆盖范围与有效条件。 |
| REV-06 | §3 Causality、§6 因果推断 | 关联、机械依赖、声明的触发关系与统计因果是不同边。trace_id 不证明因果；一次修复后测试转绿也不证明唯一根因。 |
| REV-07 | §9 初始十个 crate | 首版拆分过度，接口尚未稳定就承担跨 crate 演进成本。采用四个小 crate，先实现单项目单写入流。 |
| REV-08 | §8 重演、§10 V0.5 | 重演安全应提前进入威胁模型，但不应先承诺任意生产工作流重演。首版只做投影重建；受限实验作为下一道单独验收门。 |

以上是评审意见，不自动改变 DEC-001–DEC-012，也不宣布替代方案被采纳。

## 3. 技术事实与保证边界

**[事实]** RFC 9162 给出 Merkle 包含与一致性证明，并明确不同客户端看到不一致视图的问题。包含证明说明某叶属于某个根；一致性证明说明两个已知根对应的前缀关系。它们不证明现实事件完整，也不自动消除日志分叉。[S1]

**[事实]** JCS 禁止重复键，保留字符串原样，不做 Unicode 规范化；键排序以 UTF-16 code unit 为依据。普通 JSON 序列化或 Rust 字符串排序不自动等于 JCS。[S2] CBOR 同样需要选择明确的确定性编码配置，不能只写“canonical CBOR”。[S3]

**[事实]** DSSE 将 payload type 与精确内容字节纳入签名；keyid 只是非认证提示，不能充当授权依据。[S4] Ed25519 的算法与测试向量见 RFC 8032；选择算法仍须另行定义信任根、权限与撤销。[S5]

**[事实]** PostgreSQL 的 nextval 在事务回滚后不回收，不能提供无缺号序列；Serializable 事务也可能需要完整重试。[S6–S7] RLS 可被超级用户及 BYPASSRLS 角色绕过，不能防御数据库管理员。[S8]

**[事实]** SLSA 工件验证包含可信 builder 身份、签名及预期构建参数等检查；签名有效不是安全测试充分的证明。[S9] Temporal replay 是按历史检查工作流生成的 Commands，不是任意外部世界的复原。[S10] WASI 文件访问采用能力模型；实际沙箱保证仍取决于授予的能力与宿主接口。[S11]

## 4. 最小协议与信任模型

**[假设]** 首版使用受限 JCS JSON、SHA-256、Ed25519 与明确 DSSE payload type；不自行设计签名编码。所有计数器使用受约束的十进制字符串；协议不接受浮点数、重复键、未知关键字段或无限深对象。编码规范与负例向量先于实现冻结。

| 记录 | 最小字段与语义 |
|---|---|
| Statement | schema/type、tenant/project/source、source_epoch/source_sequence、来源时间及精度、动作、对象摘要、typed parent refs、证据引用；签名覆盖精确规范字节。 |
| Receipt | log_id/epoch、连续 leaf_index、statement digest、平台观察时间、授权政策版本；平台分配，不能伪称来源确认。 |
| Assessment | subject digest、rule/policy digest、verifier/environment identity、evidence digests、结果、范围、有效条件；追加发布，可被后续结论取代。 |
| Checkpoint | log_id/epoch、tree_size、root、算法配置、签署者及签名；可信根从外部配置输入，禁止相信包内自带公钥。 |
| Coverage | 已登记来源、采集范围、游标／时间窗、核对结果、已知缺口；只能表达该范围内的覆盖。 |

稳定 event_id 与内容摘要分开。签名不包含自身；Receipt 引用来源 envelope 摘要，Merkle 叶提交确定的 Receipt 字节；后到证据和验证结果以新记录关联，禁止回填旧叶。叶索引、树大小、域分离、空树与非二次幂树形必须写入协议。协议升级只能产生可识别的新版本，不能重新编码已承诺历史。

来源权限分为“提交陈述”“签署构建结果”“调整验证政策”“签署检查点”。Agent 不能给自己扩权或修改门禁。Webhook 由适配器认证后记录时，适配器签名只证明适配器观察到了内容；不得标为上游平台对内容的密码学签名。不同角色使用不同凭证与治理路径。

**[假设]** 防御范围：传输错误、重复提交、普通采集器故障、受限来源伪造、存储修改、已固定历史回滚。恶意来源可以撒谎；管理员与日志签名密钥同时失陷时，只有外部已保存承诺保护过去。来源、验证器和见证者全部串谋不在保证内。多个同一管理员控制的见证节点不构成独立信任域。

尾部截断必须相对外部检查点检测；离线包无法知道全网最新头，应输出“验证至 tree_size=N，最新性未知”。分叉检测需要比较根或一致性证明；永不交换观察的两组客户端可能长期看见不同历史。事件遗漏需要来源清单、游标核对、投递回执及约定期限；对从未经过任何可观察边界的操作，系统不能证明它未发生。

## 5. 事务与故障恢复状态机

**[假设]** 单项目日志使用事务内锁定的计数器分配 leaf_index，禁止用 BIGSERIAL 缺号推断遗漏；索引与账本行在同一事务提交。CAS 与数据库不宣称跨系统原子提交。

| 阶段／故障点 | 约束与恢复 |
|---|---|
| 收到来源记录 | 验证字节、来源权限、大小；同一幂等键同摘要返回已有 Receipt，不同摘要报冲突。 |
| 证据进入 CAS | 先校验并确认对象持久化，再允许声明 available；失败保持未完成，不出成功回执。 |
| DB 事务提交 | 锁定流，分配索引，追加记录与 outbox；崩溃回滚后重试。 |
| CAS 完成但 DB 未提交 | 留下孤儿对象，由宽限期 GC 清理；不得误删有效引用对象。 |
| DB 已提交但 ACK 丢失 | 重投返回同一 Receipt；accepted 与已固定／已见证是不同状态。 |
| 检查点签署 | 只签已提交的确定前缀；投影或上传通知失败由 outbox 重试，不改账本。 |
| 数据库恢复到旧备份 | 与外部固定头比较；不足时停止继续签署并进入恢复／隔离，禁止从旧头悄悄分叉。 |
| 投影损坏 | 从原始已承诺记录重建；不允许拿投影内容覆盖账本。 |

CAS 读不到对象时，历史承诺仍可核验，但重建与性质验证必须报告 INCOMPLETE。ACK 的持久化等级、备份恢复点、孤儿对象宽限期均待实测和 ADR 裁决。

## 6. 时间、状态、隐私与重演

来源发生时间、平台观察时间、账本索引与有效时间分别保存。来源时钟允许缺失或不准；排序只提供入账顺序。parent 边应带关系类型、来源与证据。后到父节点保持 unresolved，不猜测；循环依赖进入隔离／错误报告，而关联图无需强行成为 DAG。W3C PROV 的 Entity/Activity/Agent 与 derivation 可用作语义映射，不代表统计因果证明。[S12]

**[假设]** State 是投影结果，绑定 checkpoint、projector/schema 版本、覆盖声明和查询时间语义。区分“当时系统知道什么”与“现在根据晚到记录解释过去”。快照是缓存；同一输入与版本应重建同一摘要。代码 SHA 不能单独恢复环境，还要保存源码对象、依赖、工具链、配置与可获取性；不保存的外部输入必须声明未知。

隐私不能以 tombstone 代替实际删除。最小不可变元数据与可删除敏感内容分层；内容按租户加密与授权，禁止提供全局可探测的摘要查找。低熵明文哈希也会泄露信息，公开承诺需评估随机盐或加密内容承诺。删除涵盖对象、缓存、索引、投影、导出与备份生命周期；已分发的明文无法收回。crypto-erasure 取决于所有密钥副本与明文副本的处理，不自动证明法律合规；媒体清理参考 NIST 指南。[S13] 删除后应明确显示“承诺仍存在，内容不可用，无法重建”。

**[假设]** 首版 reconstruction 不执行历史命令。后续 re-execution 从精确清单启动临时环境，默认无生产凭证、无外网、无宿主写权限；支付／邮件／部署只允许明确模拟接口。容器标签不是安全证据。验证拒绝逃逸、网络、资源耗尽与凭证访问，再允许受限实验；重演产生新 Experiment 记录，不能写回旧事实。LLM 输出、外部服务与并发调度不能承诺确定性复现。

## 7. 离线验证器与小规模 Rust Workspace

**[假设]** 使用四个 crate：

- `chronicle-protocol`：字段、限制、规范编码与测试向量。
- `chronicle-core`：追加／去重、检查点与确定性投影；不包含 UI 或实验执行。
- `chronicle-cli`：采集、导出、查询与 PostgreSQL/CAS 接口。
- `chronicle-verifier`：只读离线包，独立进程，无数据库、网络、执行插件或秘密依赖。

其余目录为 `docs/{threat-model,protocol,adr}`、`fixtures/`、`migrations/`、`tests/{fault,tamper,acceptance}`。只集成一个 CI 来源；Cargo Workspace 管理共同锁文件与构建，具体依赖版本实施时再核实。[S14]

验证器接受外部 trust policy 与已固定 checkpoint，输出分项结果：BYTE_INTEGRITY、SIGNATURE、AUTHORIZATION、PREFIX_CONSISTENCY、EVIDENCE_AVAILABILITY、POLICY_RESULT、COVERAGE、FRESHNESS。拒绝以单一“PASS”混淆保证。

主服务与离线验证器共享核心会产生共同缺陷；独立进程只解决运行依赖，不解决算法独立性。首版用标准向量、人工负例与独立测试生成器减轻风险；高保证版本再以第二种实现交叉核验编码、Merkle 和协议解释。不要仅让同一库生成证明再由自身验证。

## 8. 可执行 MVP 验收矩阵

本表是未来实施验收规格，**本轮未运行产品测试**。所有负例保留输入包、期望结果、执行日志与精确代码版本。

| ID | 输入／攻击 | 验收结果 |
|---|---|---|
| M01 | 一个真实 Rust 提交测试失败，修复提交复测 | 两次真实结果绑定不同 commit、规则、环境及日志；失败不被覆盖。 |
| M02 | 同一来源记录重投100次；同键换内容 | 仅一条入账；换内容显式冲突，不能静默更新。 |
| M03 | 在 CAS、事务、ACK、outbox 各边界终止进程 | 恢复后已承诺记录不丢失、无重复成功回执；孤儿可解释。 |
| M04 | 篡改事件／证据字节；交换叶序 | 摘要或根核验失败，定位失败类别。 |
| M05 | 删除末尾记录并重签；恢复旧备份 | 相对外部固定头拒绝回滚；无固定头时明确无法证明最新性。 |
| M06 | 同大小不同根；不同大小不一致根 | 显式 fork／consistency failure；见证观察隔离时不谎称已检测。 |
| M07 | 重复键、Unicode排序边界、超深JSON、大整数、未知关键字段 | 按冻结配置拒绝或产生规定字节；跨实现向量一致。 |
| M08 | 来源合法签名但提交越权类型；包内伪造信任根 | 授权失败；包内密钥不能改变外部 trust policy。 |
| M09 | 删除证据、换环境、过期报告、Agent自设VERIFIED | INCOMPLETE／STALE／授权失败；不得放行对应门禁。 |
| M10 | 打乱到达顺序、晚到父节点、冲突／循环边 | 当前解释与历史已知视图区分；缺口和冲突可查询。 |
| M11 | 删除投影再重建；替换 projector 版本 | 同版本摘要一致；版本改变产生新结论并保留旧版本。 |
| M12 | 与来源CI作业清单核对并故意漏一项 | 声明范围内报告缺口；不承诺未登记来源的完整性。 |
| M13 | 跨租户读取、删除敏感资产后读取／重建 | 拒绝越权；删除副本按声明范围验证，重建报告内容不可用。 |
| M14 | 导出护照后断网、停止主服务再核验 | 离线工具完成分项核验；未知最新性与缺失内容显式报告。 |

推进次序：冻结威胁与字节协议→事务／篡改负例→真实失败修复样本→离线护照。吞吐与延迟只报告实测条件和分布，不把 Genesis 的 P95 2秒草案标为已达到。

## 9. 替代架构与待裁决取舍

| 方案 | 获益 | 成本／边界 | 评审建议 |
|---|---|---|---|
| 单项目顺序日志＋外部固定头 | 容易解释提交边界、恢复与完整前缀 | 单流写入瓶颈；管理员仍影响未固定历史 | MVP采用假设，先测容量。 |
| 每来源签名流＋跨流DAG | 保留离线并行与来源独立排序 | 分叉处理、跨流覆盖、投影更复杂 | 多来源确有需求后评估。 |
| 直接采用第三方透明日志 | 少维护部分见证设施 | 隐私、可用性、数据公开与权限成本 | 可作承诺出口，不替代本地采集与授权。 |

**[研究]** ZK、统计反事实、确定性仿真、自动架构搜索、全工程孪生均延后。它们需要独立实验与失败准则，不能借账本完整性升级为事实正确性。

待裁决 ADR：①威胁与覆盖范围；②Statement/Receipt/Assessment字节协议；③信任根、来源权限与轮换；④检查点固定与灾难恢复；⑤保留／删除边界；⑥投影版本与时间语义。上述意见不构成用户批准、第三方裁决或代码交付。

## 10. 一手资料与本轮检索记录

均于本轮实际打开；URL 为官方来源或协议维护者仓库。动态页面的“current”不代表本项目已经选择对应软件版本。正文以短技术事实引用，方案均为评审建议。

| 编号 | 文档／核查点 | 原始 URL | 检索引用 |
|---|---|---|---|
| S1 | RFC9162，§2.1、§11，包含／一致性／不同视图 | https://www.rfc-editor.org/rfc/rfc9162.html | turn3view0 |
| S2 | RFC8785，§3.1–3.2，JCS约束 | https://www.rfc-editor.org/rfc/rfc8785.html | turn3view1、turn4view10 |
| S3 | RFC8949，§4.2，确定性编码配置 | https://www.rfc-editor.org/rfc/rfc8949.html | turn3view3、turn5view9 |
| S4 | DSSE Protocol，payload type、PAE、keyid | https://github.com/secure-systems-lab/dsse/blob/master/protocol.md | turn3view4、turn4view9 |
| S5 | RFC8032，EdDSA与测试向量 | https://www.rfc-editor.org/info/rfc8032/ | turn4view6、turn5view10 |
| S6 | PostgreSQL sequence回滚与缺号 | https://www.postgresql.org/docs/current/functions-sequence.html | turn3view6、turn4view8 |
| S7 | PostgreSQL事务隔离与重试 | https://www.postgresql.org/docs/current/transaction-iso.html | turn2search1 |
| S8 | PostgreSQL RLS绕过权限 | https://www.postgresql.org/docs/current/ddl-rowsecurity.html | turn3view7、turn4view7 |
| S9 | SLSA工件核验 | https://slsa.dev/spec/v1.2/verifying-artifacts | turn3view5、turn5view0 |
| S10 | Temporal Replay语义 | https://docs.temporal.io/workflow-execution | turn4view4、turn5view7 |
| S11 | Wasmtime/WASI安全边界 | https://docs.wasmtime.dev/security.html | turn4view2、turn5view6 |
| S12 | W3C PROV-DM，来源与派生 | https://www.w3.org/TR/prov-dm/ | turn4view1、turn5view8 |
| S13 | NIST媒体清理指南入口 | https://csrc.nist.gov/pubs/sp/800/88/r2/final | turn4view3 |
| S14 | Cargo Workspace | https://doc.rust-lang.org/cargo/reference/workspaces.html | turn4view5 |

本轮未核查模型发布日期，未继承先前聊天中的版本或发布结论；未计算原Genesis字节摘要、未运行产品实现、未生成第二个独立评审者署名。
