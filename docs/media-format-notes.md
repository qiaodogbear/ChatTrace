# 微信 4.x 聊天媒体格式与解密：实测结论（ChatTrace M3 笔记）

> 环境：Windows 微信 **4.1.12.55**，真实账号数据（24–25 个加密库，已由 ChatTrace 解密）。
> 本文是 ChatTrace 0.3.0 媒体导出功能的实现依据，也为后续"V2 图片运行时密钥"研究留档。
> 所有结论均在真实数据上验证过（样本量见各节）。

## 1. 消息 → 磁盘文件：关联键

| 媒体 | 磁盘位置 | 关联方式 |
| --- | --- | --- |
| 图片 | `msg\attach\<md5(会话 username)>\<yyyy-MM>\Img\<md5>_W.dat`（原图）· `<md5>_t_W.dat`（缩略）· `<md5>.dat` / `<md5>_t.dat`（V2 时期） | 消息行 `packed_info_data` 内嵌 32 位 hex md5 |
| 视频 | `msg\video\<yyyy-MM>\<md5>.mp4` + `<md5>_thumb.jpg`（**明文，无加密**） | 同上（packed md5） |
| 语音 | **无独立文件**：在已解密的 `message/media_*.db` 的 `VoiceInfo` 表 | `username → media db Name2Id.rowid = chat_name_id`，再按 `local_id` 命中 |
| 文件（49） | `msg\file\<yyyy-MM>\<原名>`（明文原名） | ✗ 消息级关联需解密 XML，未实现 |

要点：

- `packed_info_data` 是 protobuf 风格字节串，md5 以 **32 个小写 hex ASCII** 内嵌，实测
  **3817/3817** 条图片消息均可解出；形态有 40 / 42 / 44 / 45 / 46 字节多种，稳妥提取法：
  对整个 packed 正则 `[0-9a-f]{32}(?![0-9a-f])`。
- `msg\attach` 顶层 32hex 目录名 == 消息所在 `Msg_<hash>` 表的 hash 后缀 == `md5(会话 username)`。
- `VoiceInfo.voice_data` 为 **SILK v3**，头 `02 23 21 53 49 4C 4B 5F 56 33`（`\x02#!SILK_V3`）；
  实测本账号 2262 条语音可导出，且按 `local_id` 精确命中（例：`local_id=9302` 命中唯一一条，`create_time` 一致）。
- 媒体被微信清理很常见：3005 条视频消息本地只剩 350 个 mp4（约 12%），语音亦有缺失——UI 必须如实标注而非报错。

### 1.1 跨分片陷阱（曾导致 bug）

`local_id` **只在单个 shard 内唯一**，跨 shard 可重复。聊天视图把多个 shard 合并后按
`(create_time, local_id)` 排序保留最新行；若二次定位只按 `local_id` 查询，会命中另一分片的同 id 行
（表现为媒体端点返回 `skipped`）。**按 local_id 二次定位必须同时带 create_time。**

## 2. 图片 `.dat` 加密三态

判定入口：读文件前 6 字节。

| 形态 | 文件头 | 加密 | 能否离线解 |
| --- | --- | --- | --- |
| 旧式 | 非 `07 08 56 3x 08 07` | **整文件单字节 XOR** | ✅ 可以 |
| V1 | `07 08 56 31 08 07` | AES-128-ECB + 固定 key（`md5("0")` 相关）+ 尾部 XOR | ✅ 通常可以（本账号未见 V1） |
| V2 | `07 08 56 32 08 07` | AES-128-ECB，密文自 offset 15 起 | ❌ 需运行时内存 key |

### 2.1 旧式 XOR：key 从图像魔数反推

JPEG 明文头 `FF D8 FF E0`（JFIF）或 `FF D8 FF E1`（Exif），PNG 为 `89 50 4E 47`：

```
key = data[0] ^ 0xFF        # JPEG
key = data[0] ^ 0x89        # PNG
校验 data[i] ^ key == magic[i] 后整文件 XOR 即可
```

- 实测本账号 **2024-06 ~ 2025-08 全部为 `key = 0xA4`**，且 **JPEG 与 PNG 共用同一 key**
  （JPEG 头 XOR 0xA4 → `5b 7c 5b 44`；PNG 头 XOR 0xA4 → `2d f4 ea e3`，曾被误判为"未知格式"）。
- 实测 4/4 解码为有效 JPEG（含 1080×1920 原图，PIL 校验通过）。

### 2.2 V2：全账号共享 key，但只在进程内存

- 两个**不同** V2 文件的 offset 15 起**前 16 字节密文完全相同** → 同一 key 加密同一 JPEG 明文模板
  → **全账号共享一个 key**（不是每图独立）。
- 该 key 与 DB 主密钥无派生关系：已实测 master key（32B）、`master[:16]`、hex-ASCII 变体、
  `sha256/md5(master)`、`master ^ 0x3A`、`md5("0")` 系列全部试解失败。
- AES 无实用已知明文攻击 → **离线不可解**；需在微信运行（查看过图片）时从进程内存提取
  16/32 位 ASCII 候选，并用 `_t.dat[15:31]` 密文模板 AES 试解验证。
- 时间线：本账号 **2025-08 起出现 V2，2025-09 起全部为 V2**（9000 样本中 5126 个容器）。

## 3. 语音转码现状

- `ffmpeg` **没有** SILK v3 解码器。
- `pilk` 为 **GPL-3.0**（不能并入 MIT 项目，只能独立进程调用）；`kn007/silk-v3-decoder` 与 `sjzar/go-silk` 为 MIT。
- ChatTrace 0.3.0 的策略：导出**原始 `.silk`**（保真留档），不内置转码器。

## 4. 复现命令

```powershell
# 图片：解码单张 dat（XOR 0xA4）
python -c "d=open(r'<...>_W.dat','rb').read(); open('out.jpg','wb').write(bytes(b^0xA4 for b in d))"

# 语音：从已解密库导出某条语音
python -c "import sqlite3;c=sqlite3.connect(r'<dec>\message\media_0.db');b=c.execute('select voice_data from VoiceInfo where chat_name_id=? and local_id=?',(2,9302)).fetchone()[0];open('v.silk','wb').write(b)"
```
