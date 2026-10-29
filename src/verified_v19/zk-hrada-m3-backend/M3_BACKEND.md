# HRADA M3 最小联合后端

## 状态

本目录是 `cpsnarks-set` commit
`f8c7db66b7519b91dcda16caee6cb84949e8911b` 的独立实验分支。它将原先的
“单隐藏素数共同承诺”扩展成了一个可编译、可验证的最小联合后端：

1. CP-RSA 证明隐藏状态素数 `p` 是 RSA 累加器成员；
2. LegoGroth16 证明同一 `p` 由隐藏 ABAC 策略生成；
3. 公开的 `resource/action/epoch/agent_id/nonce` 与证明绑定；
4. adapter 的 `paramsHash` 绑定 CP Pedersen bases 和完整 Lego 验证密钥；
5. 组合验证流程拒绝 `p`、request 和参数拼接。
   它也拒绝同一 `p` 但使用不同 Pedersen 随机数的承诺拼接。

因此，以前审计中的 P4 “residual commitment 未实现”可以对“最小联后端”
改为 **Go**。它不等于完整 HRADA 系统已经 Go：递归委托链、范围不等式、
当前全局状态检查和 Agent 私钥持有证明仍需要接入。

## 密码绑定

LegoGroth16 的 instance 顺序固定为：

```text
[1, p, resource, action, epoch, agent_id, nonce]
```

`link_d` 为：

```text
B0 + Bp*p + Br*resource + Ba*action + Be*epoch
   + Bag*agent_id + Bn*nonce + H*r
```

残差适配验证器计算：

```text
C_p = link_d - B0 - Br*resource - Ba*action - Be*epoch
             - Bag*agent_id - Bn*nonce
```

且强制 `Bp` 和 `H` 分别等于 CP-RSA 使用的 Pedersen `g` 和 `h`。
因此残差必须等于 CP 语句中的：

```text
C_p = g*p + h*r
```

核心实现位于 `src/protocols/abac_link.rs`。

这里的 `abac_link::verify` 只验证 Lego 关系、残差相等和 adapter 参数摘要；
完整组合接受条件必须由调用方写成 `cp_membership_verify && abac_link_verify`。
它不是把两个子协议变成一个 Groth16 proof：CP-RSA 组合证明和额外的 ABAC
LegoGroth16 proof 都必须传输和验证。

## 策略与 hash-to-prime

最小 ABAC 关系使用固定位宽：

| 属性 | 位宽 | 可见性 | 约束 |
|---|---:|---|---|
| resource | 16 | 请求公开，策略私密 | 相等 |
| action | 16 | 请求公开，策略私密 | 相等 |
| epoch | 32 | 请求公开，策略私密 | 相等 |
| agent_id | 32 | 请求公开，策略私密 | 相等 |
| serial | 32 | 私密 | 固定位宽 |
| nonce | 64 | 公开 | 绑定 verifier 请求；需服务端原子消费才能防重放 |

前五项规范化打包为 128-bit 消息。电路内外都使用上游
`snark_hash` 相同的 Blake2s search-and-test hash-to-prime 关系。素性的
Miller–Rabin 检查在 issuer/累加器插入路径执行；电路证明被承诺的素数
确实是该 search-and-test 过程选中的候选值。

## 固定依赖

`Cargo.lock` 锁定：

| 组件 | Commit/版本 |
|---|---|
| cpsnarks-set | `f8c7db66b7519b91dcda16caee6cb84949e8911b` |
| legogro16 | `4df487bafaf542f0d07d2893aa646bbc4aac42a2` |
| accumulator | `35b92942059d6fb5bd3427647e0495a7af3ca315` |
| ark-bls12-381 | `666da1e3b22ad0f46418fb89d4e81eddfd7296c1` |
| num-bigint | `0.3.3` |
| Rust | `1.85-aarch64-apple-darwin` |

`num-bigint 0.3.2` 在现代 Rust 上发生 `div_ceil` 方法解析冲突，因此受控
升级为 0.3.3。`gmp-mpfr-sys` 强制使用 Homebrew GMP/MPFR/MPC，避免旧版
内置 GMP fat build 在 Apple Silicon 上的已知崩溃。

## 复现

macOS/Homebrew：

```bash
cd /artifact/repository/zk-hrada-m3-backend
./scripts/test_m3_backend.sh
```

执行包含上游协议在内的完整 19 项 release suite：

```bash
./scripts/test_m3_backend.sh --all
```

### M3-min 性能原始数据

benchmark 二进制在每次调用中只执行一次 CP-RSA setup 和一次
ABAC LegoGroth16 setup。两段 setup 单独计时，不计入在线证明时间。
例如，执行 1 次预热和 2 次测量：

```bash
./scripts/benchmark_m3_min.sh \
  --runs 2 \
  --warmups 1 \
  --seed 20260805 \
  --output results/raw/m3_min_smoke.csv
```

输出包括未删减的 CSV 与同名 `*.environment.json`。CSV 保留预热、
失败行、随机种子、`paramsHash`、源码聚合哈希和每个样本的七个
阶段：

| 阶段 | 计时边界 |
|---|---|
| `statement_prepare` | 为当前请求派生新的 Pedersen 随机数 `rho`，并生成 `C_p` |
| `cp_rsa_prove` | 完整 CP-RSA membership 证明 |
| `lego_abac_prove` | 共享同一 `p,rho` 的 ABAC LegoGroth16 证明 |
| `joint_prove` | 一次真实外层调用中的 CP+ABAC 总耗时，不是事后求和 |
| `cp_rsa_verify` | 单独 CP-RSA 验证 |
| `abac_link_verify` | 单独 Lego 关系与 residual commitment 链接验证 |
| `joint_verify` | 在一次外层调用中重新执行 CP 和 link 两项验证 |

`cpProofBytes` 使用版本化的 deterministic experimental wire encoding：
字段顺序固定，值使用 `u64-le` 长度前缀，GMP 整数显式编码符号，
RSA 元素使用上游 `ElemToBytes`，曲线元素和嵌入的 Lego 证明使用
arkworks `CanonicalSerialize`。`legoProofBytes` 直接使用
`CanonicalSerialize`；`totalProofBytes` 为两者之和，不包含语句、CRS、
累加器状态或 CSV 框架。

JSON 分别记录 `cpSetupElapsedNs` 和 `abacSetupElapsedNs`。
`linkParamsHash` 仅覆盖 CP Pedersen bases 和 ABAC Lego VK；CSV 中的
`paramsHash` 则额外绑定 RSA modulus、全部可区别 CP CRS 字段、完整
CP hash-to-prime Lego proving key 和累加器模式。动态累加器值作为
`accumulatorStateHash` 单独记录，不混入公共参数哈希。

测试在同一累加器状态中生成两个分别有效的 CP-RSA 成员证明，然后验证：

| 用例 | 预期 | 已执行结果 |
|---|---|---|
| CP(p1) + ABAC(p1, request1, params1) | 接受 | 接受 |
| 有效 CP(p2) + 有效 ABAC(p1) | 拒绝 | 拒绝 |
| CP(p1, r2) + ABAC(p1, r1) | 拒绝 | 拒绝 |
| request1 改为 request2 | 拒绝 | 拒绝 |
| params1 证明使用 params2 验证 | 拒绝 | 拒绝 |

## 仍未完成的系统工作

- 委托深度与父子权限单调收缩电路；
- 隐藏注册用户承诺与授权发行关系绑定；
- `not_before <= now <= not_after` 等不等式 ABAC；
- Agent 对 challenge 的私钥持有证明；
- 验证器对最新 accumulator/epoch 的强制获取；
- 正式可复现 setup ceremony 和持久化 CRS 序列化；
- 完整 M3 的证明时间、内存、证明大小和并发性正式实验。

此外，当前 adapter `paramsHash` 不是完整系统参数 manifest：它不覆盖 RSA
modulus 和全部 CP root/modeq CRS。部署或正式 benchmark 必须另外固定并校验完整
参数清单。当前隐藏成员只承诺策略字段和 serial，不包含注册用户承诺；“谁有权
把元素加入全局累加器”仍是可信发行服务边界。`agent_id` 只是公开的 `u32` 标识，不是 Agent 公钥，也不构成私钥
持有证明；`epoch` 只是电路内相等关系，不自行保证它是最新 epoch。

上述项目不影响 residual adapter 的密码闭环结论，但在它们完成前，
论文应表述为“最小联合后端已实现”，而不是“完整生产系统已实现”。
