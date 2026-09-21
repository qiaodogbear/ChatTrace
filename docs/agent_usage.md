# 让 agent 持续增量拉取一个群聊

面向「另一个 agent / 定时任务」的操作说明：**给定一个群聊名称，持续把新消息拉到本地文件**。
三条命令就能搭起来，不需要理解微信的存储格式。

> 前置条件：本机已完成过一次「获取密钥 + 解密数据」（见 [新手图文指南](beginner_guide.md) 第 1–3 步）。
> 之后本文件描述的全部操作都是**只读**的：只读微信原始文件，产物写到 ChatTrace 自己的缓存目录。

---

## 0. 三个名词

| 名称 | 含义 | 例子 |
| --- | --- | --- |
| `<ACCOUNT_DIR>` | 微信账号数据目录（**不是** `xwechat_files` 根目录） | `<xwechat_files>\wxid_xxx_1234` |
| **username** | 会话的稳定标识；群聊以 `@chatroom` 结尾，单聊是 `wxid_...` | `12345678901@chatroom` |
| **群聊名称** | 界面上的显示名，**可能重复、可能被改** | `某个群` |

**核心原则：先用群名解析出 username，然后把 username 固化下来。** 群名是会变的，
只靠名称轮询的话，某天改了名就会表现为「永远拉到 0 条新消息」，而这是最难察觉的故障。

---

## 1. 推荐方式：`scripts/poll_chat.py`（一条命令）

仓库自带的封装脚本把「增量解密 → 解析会话 → 增量导出 → 记录游标」串成一次调用，
并把**一行 JSON** 打到 stdout 给调用方解析：

```bash
python scripts/poll_chat.py --account-dir "<ACCOUNT_DIR>" --chat "某个群"
```

输出（stdout，单行）：

```json
{"ok": true, "chat": "某个群", "username": "12345678901@chatroom",
 "mode": "incremental", "exported": 5, "next_since": "1790005705,1236",
 "total": 10710, "output": "...\\某个群__20260922-002635.json",
 "decrypt": "0 decrypted, 25 fresh, 0 failed of 25 DBs"}
```

| 字段 | 说明 |
| --- | --- |
| `ok` | 本次是否成功；失败时为 `false` 并给出 `error` 与 `code` |
| `mode` | 首次运行是 `full`，之后是 `incremental` |
| `exported` | **本次新增消息条数**（`0` 表示没有新消息） |
| `next_since` | 下次要用的游标，已自动写盘，调用方无需自己保存 |
| `total` | 该会话的消息总数（用于判断是否首次拉取完整） |
| `output` | 本次导出的文件路径 |

常用参数：

| 参数 | 用途 |
| --- | --- |
| `--chat` | 群聊名称（子串）**或**精确 username，两者都能识别 |
| `--out-dir` | 导出目录，默认 `<account_dir>\..\_poll\<account_id>`；游标存在其下的 `.state/` |
| `--no-decrypt` | 跳过增量解密（适用于解密由别的环节负责时） |
| `--full` | 忽略游标，重导整段历史 |
| `--media` | 同时带上媒体可用性标注（图片尺寸/语音时长等） |
| `--format` | 默认 `json`；**增量模式必须是 json**，其它格式无法记录游标 |

退出码：`0` 成功 · `1` 环境问题 · `2` 群名无法解析 · `3` 导出失败 · `4` 游标读不回来。

---

## 2. 等价的原生 CLI 流程

不想用脚本时，三条命令是一样的：

```bash
# 1) 把微信里的新消息增量解密到本地（幂等，无新数据时全部 skip）
chattrace data decrypt --account-dir "<ACCOUNT_DIR>"
#    -> result: 3 decrypted, 22 fresh, 0 failed of 25 DBs

# 2) 群名 -> username（首次或群名变更后执行一次）
chattrace chat list --account-dir "<ACCOUNT_DIR>" --query "某个群"

# 3) 导出：首次不带 --since，之后带上上次的 next_since
chattrace export --account-dir "<ACCOUNT_DIR>" --user "12345678901@chatroom" \
  --format json --out "out.json"
chattrace export --account-dir "<ACCOUNT_DIR>" --user "12345678901@chatroom" \
  --format json --since "1790005705,1236" --out "inc.json"
```

`--since` 是**排他**游标，格式 `create_time,local_id`；也可以用
`--query "某个群"` 代替 `--user` 让它自己解析（但**轮询时请固化 username**）。

---

## 3. 导出 JSON 的结构

```jsonc
{
  "meta": {
    "username": "12345678901@chatroom",  // 会话稳定标识
    "display_name": "某个群",             // 当时的显示名
    "exported_at": "2026-09-22 00:26:35",
    "total": 10710,                       // 会话消息总数
    "incremental": true,                  // 本次是否为增量
    "since": "1790005376,1231",           // 本次使用的游标（全量时为 null）
    "media": false
  },
  "messages": [ /* 见下表 */ ],
  "next_since": "1790005705,1236",        // 下次调用请回传这个值
  "exported": 5                           // 本次条数 = len(messages)
}
```

单条消息字段：

| 字段 | 说明 |
| --- | --- |
| `local_id` | 会话内消息序号。**只在会话内唯一**，跨会话会重复 |
| `create_time` | Unix 秒。**同一秒可能有多条**，故排序与游标都用 `(create_time, local_id)` |
| `time` | 可读时间（本地时区） |
| `sender` | 发送者显示名（群昵称会变） |
| `sender_wxid` | **发送者的稳定身份，做去重/统计时用它**，不要用 `sender` |
| `is_outgoing` | 是否本人发出 |
| `kind` | `text` / `image` / `voice` / `video` / `file` / `link` / `quote` / `emoji` / `location` / `voip` / `card` / `system` / `other` |
| `local_type` | 微信原始类型码（排查用） |
| `text` | 文本内容；媒体消息这里是摘要（如 `[图片] 392×211 203.3 KB`） |
| `meta` | 媒体元数据（尺寸、时长、文件名、标题等），无则为 `null` |
| `links` | 从文本中提取的链接 |
| `media` | 仅 `--media` 时出现：`{kind, status, detail, size}` |

消息按 `(create_time, local_id)` **严格升序**排列，且同一次导出内**无重复**。

---

## 4. 每次运行只有三种结果

| 情况 | 表现 | 处理 |
| --- | --- | --- |
| 有新消息 | `exported > 0` | 读 `messages`，用 `sender_wxid` + `(create_time, local_id)` 入库 |
| 没有新消息 | `exported == 0`、`messages == []` | 什么也不用做；**游标保持原值**，不会丢位置 |
| 拉取失败 | `ok == false` + `code` | 见第 6 节 |

**幂等性**：重复运行同一游标始终返回 0 条；即使中途失败，下次仍从原游标继续，不会漏也不会重复。

---

## 5. 定时运行

固定间隔拉取即可，命令本身是幂等的：

```powershell
# Windows 计划任务 / DSH automation，每 10 分钟一次
python scripts/poll_chat.py --account-dir "<ACCOUNT_DIR>" --chat "某个群" --quiet
```

- `--quiet` 只保留 stdout 的那一行 JSON（进度信息在 stderr）。
- 建议间隔 ≥ 5 分钟；微信本身也是批量落盘的，再快通常没有新数据。
- 需要同时看多个群时，**对每个群各跑一次**（各自独立游标）。同一账号的
  `data decrypt` 是全局的，重复调用只会 skip。

---

## 6. 故障排查

| 现象 | 原因与处理 |
| --- | --- |
| `code: 2` `no chat matched query` | 群名写错，或该会话不在最近 400 个会话里（先 `chat list --query` 确认） |
| `code: 2` `ambiguous query` | 名称匹配到多个会话；改用精确 `--user <username>` |
| `code: 2` `pinned username ... no longer works` | 之前固化的 username 失效（账号/数据变动）；脚本已自动清除，重跑一次会按名称重新解析 |
| `code: 1` 解密失败（密钥自检不过） | 微信换号、重装或升级后密钥变了：重新走一遍「获取密钥」（第 2 步） |
| `exported` 一直是 0 但群里明明有新消息 | ① 微信未把新消息落盘（打开一次微信即可）；② 群名被改导致游标指向了别的会话——检查 `.state/*.json` 里的 `username` |
| 时间线看起来乱序 | 0.5.1 之前版本存在跨页乱序，升级到含 `--since` 的版本即可 |

**密钥过期提示**：`data status` 可能显示 `EXPIRED (>24h)`，这只是 TTL 到期提醒。
只要自检通过（`data decrypt` 能正常 skip/decrypt），就仍然可以用来解密。

---

## 7. 相关文档

- [新手图文指南](beginner_guide.md) —— 首次部署的五步流程
- [媒体格式与解密笔记](media-format-notes.md) —— 图片/语音的格式与解码原理
- `scripts/poll_chat.py` —— 本文件描述的封装脚本（`--help` 有完整参数）
