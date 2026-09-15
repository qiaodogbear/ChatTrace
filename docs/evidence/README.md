# docs/evidence —— 实测验证资产归档

本目录保存 2026-09-03 在本机（微信 4.1.12.55）完成端到端闭环验证时使用的脚本副本，
供 M1 实施对照与回归调试。**均以原样保留，新工程代码在 `src/chattrace/` 中另行重构。**

| 文件 | 用途 | 重构去向 |
|---|---|---|
| `locate_mmv1.py` | MMV1 魔数/rip-rel 引用静态定位 | → `keyagent/locate_anchors.py` |
| `find_entry.py` | 函数入口回溯（prologue） | → `keyagent/locate_anchors.py` |
| `disasm_anchors.py` / `disasm_anchors2.py` | capstone 反汇编核对 | 调试工具 |
| `frida_attach_probe.py` | 只读 attach 验证 | → `keyagent/wechat_state.py` 思路 |
| `frida_reg_probe.py` | CpuContext 寄存器读取验证（必须用 `this.context`） | 调试工具 |
| `frida_spawn_v3.py` | spawn 抓 key + HMAC 自检 + 清理（主线） | → `keyagent/agent.py` |
| `decrypt_wechat_dbs.py` | 批量解密 7 库（SQLCipher4 页解密） | → M2 DecryptService |

## 关键常数（4.1.12.55，RVA，详见顶层方案附录 A.2）

- codec 配置函数入口 `0x353BC60`（hook 点，`this.context.rcx` 前 32B = 主密钥）
- MMV1 字符串引用点 `0x353BC99`；魔数校验点 `cmp [rcx],'MMV1'` `0x7050502`
- 派生：`enc_key = PBKDF2-HMAC-SHA512(password, db_salt, 256000, 32)`
  `mac_key = PBKDF2-HMAC-SHA512(enc_key, db_salt ^ 0x3A, 2, 32)`；页 HMAC-SHA512 覆盖
  `页[:-64] + 页号(4B LE)`；reserve = 80；页 1 布局 `[0:16]salt | … | [4016:4032]IV | [4032:4096]HMAC`

## 敏感文件注记

`wx_password.bin`（32B 主密钥）与 `wx_hits.jsonl`（含内存 dump 候选）**不归档入库**，
按用户要求保留于 `%TEMP%`，由用户自行管理。任何提交不得包含此类文件。

> 同理，脚本中的**账号目录与微信安装路径已替换为占位符**（可用 `CHATTRACE_ACCOUNT`、
> `CHATTRACE_WECHAT_ROOT`、`CHATTRACE_WEIXIN_EXE`、`CHATTRACE_MSG0_DB` 环境变量覆盖）。
> 这些脚本是当日实测的原样留档，运行前请按本机情况设置环境变量。
