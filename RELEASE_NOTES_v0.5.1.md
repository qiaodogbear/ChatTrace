# ChatTrace 0.5.1

面向「定时把某个群聊的新消息拉下来」这一用法：**增量导出**、一处会静默错乱时间线的**顺序缺陷修复**，
以及一个把整套流程封装成单条命令的脚本。

## 新增：增量导出（`--since`）

以前每次导出都是全量。现在 `export` 接受一个排他游标，只导出比它更新的消息：

```bash
chattrace export --account-dir "<ACCOUNT_DIR>" --user "<username>" \
  --format json --since "1790005705,1236" --out inc.json
```

- 游标格式 `create_time,local_id`，与 `chat read --before` 对称；
- JSON 输出的 `meta` 里回传 `since` 与 `incremental`，顶层新增 `next_since` 与 `exported`，
  下次调用直接把 `next_since` 传回即可；
- **空结果也回传游标**，所以轮询不会因为某次没有新消息而丢失位置；
- `txt` 输出会在头部标注 `Since: …`；非 JSON 格式无法记录游标（脚本中会自动降级为全量提示）。

## 修复：跨页导出会导致时间线前后交错

`iter_chat_all()` 声称按「最旧到最新」输出，实际上每 2000 条一页、**页与页之间是倒序的**
（页内升序、页间降序）。后果是：一个上万条的群，导出结果会被切成若干段前后交错。
**这类错误不报错、不丢数据，只会让上层的时间线悄悄错乱**——对"持续增量拉取"尤其致命。

现在分页改为正向（`_chat_page_rows(ascending=True)`），逐页流式产出，顺序正确且内存有界
（不再需要把全部页缓存下来排序）。

真机验证（单群 10,710 条）：

| 场景 | 结果 |
| --- | --- |
| 全量导出 | 10,710 条，`(create_time, local_id)` **严格升序**，0 重复 |
| 同游标重跑 | `exported = 0`，游标保持不变 |
| 游标回退 5 条 | 正好取回那 5 条，`next_since` 与全量末游标一致 |

## 新增：`scripts/poll_chat.py`

把「增量解密 → 解析会话 → 增量导出 → 记录游标」封成一次幂等调用，给 agent 一行 JSON：

```bash
python scripts/poll_chat.py --account-dir "<ACCOUNT_DIR>" --chat "某个群" --quiet
```

```json
{"ok": true, "chat": "某个群", "username": "12345678901@chatroom", "mode": "incremental",
 "exported": 5, "next_since": "1790005705,1236", "total": 10710,
 "output": "…\\某个群__20260922-002635.json", "decrypt": "0 decrypted, 25 fresh, 0 failed of 25 DBs"}
```

- **固化 username**：首次解析出的 username 存在 `<out-dir>/.state/<群名>.json`，
  之后群名被改也不会把轮询悄悄指向另一个会话（这是最难察觉的故障模式）；
- 退出码区分「群名解析不了」(2) 与「导出失败」(3)，便于自动化分流；
- 输出目录默认在 `%LOCALAPPDATA%\ChatTrace\accounts\<账号>\poll`，
  **绝不写进微信数据目录**（该目录全程只读）。
- 进度信息走 stderr，`--quiet` 后 stdout 只剩那一行 JSON。

## 新增：`docs/agent_usage.md`

给外部 agent 的操作手册：三条 CLI 步骤、导出 JSON 的逐字段说明、三种运行结果的含义、
定时建议，以及排查表（含「群名被改后表现为永远 0 条新消息」这一坑）。

## 测试

106 → **112**：跨页顺序回归、游标排他性与同秒并列的 `local_id` 断tie、JSON/txt 增量语义。

## 已知限制

- 增量模式目前只在 `--format json` 下跟踪游标；`txt` / `html` 需要全量导出。
- 发布包里的 `ChatTrace.exe` 是「双击启动 Web UI」的入口，**不转发 CLI 子命令**；
  `poll_chat.py` 需要源码/venv 环境运行。
- WxAM（`wxgf`）原图仍回退到缩略图（见 0.5.0 说明）。
