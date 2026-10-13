# ClearAPI PG-02 Pool WebSocket r3 离线最终验收报告

最终状态：**FROZEN — PASS**。

候选 `clearapi-pg02-r3-stagingdiag-fae4c8d43d59` 已完成离线本地 Mock 验收。12 个 required Gate 全部绑定当前 r3 tagged Executor 身份，证据文件均存在且原始退出码为 0；没有部署、生产访问或真实 Provider 出网。

## 1. 冻结身份

冻结清单：`validation-r3/candidate-freeze-manifest-r3.json`

- manifest 状态：`FROZEN`，`freeze_complete=true`
- manifest SHA256：`5bf1c40ccc1f04ca65d02e4e68e983720d4096c2331223536be98097876aef77`
- 网络：`none`
- 平台：`linux/amd64`
- r3 源码 SHA256：`fae4c8d43d5971d38baf5b22660c733b71bfc384104c70759104fc5f8b041c23`
- tagged Executor 版本：`clearapi-pg02-r3-fae4c8d43d59-stagingdiag`
- build tag：`clearapi_staging_observability`
- Executor SHA256：`f5d08d9b6b32b71b7b2cac0bddc3152808ee2013c6d302e850b58c8d0a348cfa`
- 可复现重建 SHA256：`f5d08d9b6b32b71b7b2cac0bddc3152808ee2013c6d302e850b58c8d0a348cfa`
- Gateway 源码 SHA256：`972436ae1e46da815490c4191bbe32b0836cd324ce59c47a5e8b212583c6bb44`
- Gateway 二进制 SHA256：`80477fbdea163b5d243e129b4933ed8307705c4a89df93e85777f515e0423bd7`

完整身份见 `validation-r3/tagged-build-identity.json`、`validation-r3/gateway-identity.json`。Receipt candidate 使用 tagged binary；历史未带 tag 的二进制及初始失败目录不计入本候选。

## 2. Required Gate 结果

| Gate | 结果 | 关键结果 | 证据 |
|---|---|---|---|
| Receipt service | PASS | ordinary 400：A=1/B=0；Mock 总计 A=4/B=0/total=4；正向绑定、9 项负向绑定、重启区分、权限、写失败 UNKNOWN/no-replay 全通过 | `validation-r3/receipt-stagingdiag-20261011-092344/out/service-summary.json` |
| WebSocket 三轮 | PASS | 3 轮；A=3/B=0；下游握手 1 次、上游握手 1 次；最终无 in-flight/pending identity | `validation-r3/staging-v5-three-rounds/out/summary.json` |
| Capability revoke | PASS | 撤销后 eligible=0；拒绝原因 `pool_registry_not_current`；未产生额外 upstream replay | `validation-r3/staging-v5-cap-capability/out/summary.json` |
| Trust revoke | PASS | 两个 synthetic identity 均 revoked；eligible=0；拒绝原因 `pool_registry_not_current`；无 in-flight | `validation-r3/staging-v5-trust-trust/out/summary.json` |
| Auth disable | PASS | 禁用后 eligible=0；拒绝原因 `auth_unavailable`；无额外上游握手 | `validation-r3/staging-v5-dis-disabled/out/summary.json` |
| Gateway → Executor → Mock/账务 | PASS | ordinary 400：A=1/B=0；总计 A=3/B=0；UNKNOWN 不重试、不退款；重复 final usage 单次结算 | `validation-r3/staging-v6-gateway/out/core-service-summary.json` |
| Tagged focused tests | PASS | Go focused tests，tagged binary/source，退出码 0 | `validation-r3/tagged-focused.command.json` |
| Tagged runtime race | PASS | race tests，退出码 0 | `validation-r3/tagged-runtime-race.command.json` |
| Pool regression race | PASS | pool/receipt/replay 等回归 race tests，退出码 0 | `validation-r3/tagged-pool-regression-race.command.json` |
| Reproducible build | PASS | network=none、GOPROXY=off、CGO_ENABLED=0，字节级 SHA 一致 | `validation-r3/rebuild-stagingdiag-repro.command.json` |
| Relaykit offline build | PASS | locked module cache、network=none、`go build ./...`，退出码 0 | `validation-r3/relaykit-20261011/build-locked.command.json` |
| Resource cleanup | PASS | 所有候选容器/私有卷均已移除或确认不存在 | `validation-r3/cleanup-pass-resources.json` |

Manifest 中 `unresolved_gates=[]`；所有列举证据存在，且所有 Gate 的 `raw_exit_code=0`。

## 3. 安全与合同保持

- 仅使用本地 Mock、合成模型 `gpt-5.6-luna` 和合成账号 `synthetic-offline-account-0/1`。
- Receipt fixture 在隔离副本中显式补授 `stream_text`，并重算 checkpoint digest/integrity；未放宽生产授权路径。
- 保留 CAS、Fence、Attempt/no-replay、credential digest、Trust/Capability/Auth generation/revision 检查。
- WebSocket 三轮复用同一连接，未通过重复 upstream handshake 或新建连接伪造轮次。
- 写失败保持 UNKNOWN，未重放请求；Gateway 集成确认 UNKNOWN 不退款、重复 final usage 单次结算。
- 当前候选未修改 Go 产品源码；仅使用验收辅助脚本、隔离 fixture 与证据文件。诊断及历史失败证据不作为本候选结论。

## 4. 资源、范围与排除项

所有验收容器使用 `network=none`；最终清理记录显示候选容器和私有卷均已移除或已不存在。未部署 Staging/Production，未访问生产数据库，未使用真实 Provider 凭据，未推送分支。

历史证据明确排除：

- `receipt-r3-20261011-091335` 初始失败 Receipt 运行；
- `staging-three-rounds`、`staging-capability`、`staging-trust`、`staging-disabled` 旧候选目录；
- 所有 pre-tagged Executor 二进制及其服务 Receipt。

## 5. 结论

PG-02 ClearAPI Pool WebSocket r3 满足本次离线验收要求，可作为当前 **FROZEN candidate** 保留。该冻结仅表示本地 Mock 验收通过，不构成生产部署批准或真实 Provider 运行批准。
