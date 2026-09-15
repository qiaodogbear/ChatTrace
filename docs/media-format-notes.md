# 微信 4.x 聊天媒体格式与解密：实测结论（ChatTrace 媒体笔记）

> 环境：Windows 微信 **4.1.12.55 / 4.1.13.65**，真实账号数据（约 25 个加密库，已由 ChatTrace 解密）。
> 本文是 ChatTrace 媒体导出与解码功能的实现依据；**V2 图片密钥已在 0.5.0 完整攻破并落地**（见 §2.2）。
> 所有结论均在真实数据上验证过（样本量见各节）。

## 0. 消息体是 Zstandard 压缩的（M4 关键发现）

绝大多数富媒体消息的 `message_content` **不是文本**，而是 Zstandard 压缩帧
（魔数 `28 b5 2f fd`，`WCDB_CT_message_content = 4` 标记压缩；旧行 `= 0` 为纯文本）。
`source` 列几乎总是压缩（`WCDB_CT_source = 4`，实测 463,463 行）。

把它当字符串读 → 满屏 `\ufffd` 乱码（这正是早期版本"乱码/错位"的根因）。
解压之后是一份完整 XML，媒体元数据都在里面：

| 类型 | 根元素 | 可用字段 |
| --- | --- | --- |
| 图片 | `<img>` | `md5`（原图 md5，**与本地文件名不同**）、`aeskey`、`length`、`cdnthumbwidth/height`、`encryver` |
| 语音 | `<voicemsg>` | `voicelength`（毫秒）、`length`、`aeskey`、`voiceformat` |
| 视频 | `<videomsg>` | `md5`、`aeskey`、`length`、`playlength`（秒）、缩略图尺寸 |
| 文件/链接/引用/小程序 | `<appmsg><type>N</type>` | `title`、`des`、`url`、`md5`、`fileext`；`type=57` 为引用，内含 `<refermsg>`（`fromusr`/`chatusr`/`content` 是**子元素**不是属性） |
| 位置 | `<location>` | `x`/`y`（经纬度）、`poiname`、`cityname` |
| 语音通话 | `<voipinvitemsg>` + `<voiplocalinfo>` | `diaplay_content`（如"通话时长 01:20"） |
| 名片 | `<msg … username nickname …>` | `nickname`、`username`、`alias` |
| 表情 | `<emoji>` | `md5`、`len`、`cdnurl`（本地通常无缓存文件） |

群聊文本消息还带发送者前缀：`<发送者wxid>:\n<内容>`——比 `Name2Id` 映射更可靠。

## 0.1 Name2Id 的 rowid 是分片内局部的

同一个 username 在不同 shard 里 rowid 完全不同（实测：`message_1.db` 里 rowid=1051、
`message_2.db` 里 rowid=11、`message_3.db` 里 rowid=386）。把各分片的 `Name2Id`
合并成一张表去解析 `real_sender_id` 会让**人名与消息内容错位**。
正确做法：用行所属分片自己的 `Name2Id`。发送者优先级：
群前缀 → 本分片 Name2Id → `status == 2` 启发式。

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
| V2 | `07 08 56 32 08 07` | AES-128-ECB（密文自 offset 15 起）+ 尾部单字节 XOR | ✅ 可以（密钥由 `kvcomm code + wxid` 离线派生，见 §2.2） |

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

### 2.2 V2：密钥可完全离线派生（0.5.0 攻破）

V2 是"三段拼接"容器，分段长度写在文件头里：

```
[15B 头][AES-128-ECB 密文][单字节 XOR 尾部]

头 := 07 08 "V2" 08 07 | u32le aes_size | u32le xor_size | 1B 占位
```

**最容易算错的一点**：AES 段按 PKCS7 补齐到 16 的整数倍，而 `aes_size` 本身已经是 16 的倍数时
**仍会再多占一个块** —— 真实密文长度是 `aes_size + 16 - (aes_size % 16)`
（本账号 `1024 → 1040`）。把多出来的这 16 字节误当成"明文段"，分段就会整体错位。

**两把钥匙都能从本机文件推导，不需要微信在运行：**

| 量 | 来源 | 示例（合成） |
| --- | --- | --- |
| `code` | `%APPDATA%\Tencent\xwechat\*\kvcomm\key_<code>_*.statistic` 的文件名 | `1234567` |
| `xor_key` | `code & 0xFF` | `0x87` |
| `aes_key` | `md5(f"{code}{wxid}").hexdigest()[:16]`，作为 16 字节 ASCII 使用 | `7afad634d235415a` |

其中 `wxid` 取账号目录名去掉尾部数字后缀（`wxid_demo0000_1234` → `wxid_demo0000`）。
**上表是合成的演示值**：真实账号的 `code` 与派生密钥不写入仓库——两者结合即可解密该账号的全部图片。
本机实测的 `xor_key` 与旧式图片的 XOR key 恰好一致（同一账号下两者相同）。
**校验方式**：用候选 key 以 AES-ECB 解密任一 V2 文件 offset 15 起的 16 字节，明文应为图片魔术
（`FF D8 FF E0/E1`、`89 50 4E 47`…）。不同 V2 文件的首块密文完全相同，正是因为它们的明文首块
都是同一个 JPEG JFIF 头。机器上可能同时存在多个 `code`，因此必须逐个校验后才采用。

- 与 DB 主密钥无派生关系（32B master、`master[:16]`、hex-ASCII、`sha256/md5(master)`、
  `master ^ 0x3A`、`md5("0")` 系列全部试解失败）；也与消息 XML 里的 per-image `aeskey` 无关
  （后者用于 CDN 传输，实测对本地 dat 无效）。
- **不需要读进程内存**。曾对运行中的微信做全内存搜索（1.4 GB 可读写区 + 1.1 GB 全量区、
  ASCII 与 UTF-16 两种编码的候选、16 字节对齐与逐字节暴力共 15 亿+ 次 AES 尝试）全部落空——
  原因正是 key 根本不以明文常驻内存，而是每次由 `code` 现算。
- 时间线：本账号 **2025-08 起出现 V2，2025-09 起全部为 V2**（9000 样本中 5126 个容器）。
- **同一 md5 下并存三档文件**：`<md5>_h.dat`（高清原图，实测 4096×3072 / 8.8 MB）、
  `<md5>.dat`（中图——消息 XML 的 `width`/`height`/`length` 描述的正是这一档）、
  `<md5>_t.dat`（缩略图，对应 `cdnthumbwidth`/`cdnthumblength`）。
  ChatTrace 按"原图优先"选择，并**测量被选中文件本身**的像素尺寸，避免"标注是缩略图尺寸、
  显示的却是原图"这种自相矛盾。
- **分段长度不固定**：实测 `aes_size` 恒为 1024（→ 1040 字节密文），而 `xor_size` 从 1.5 KB
  到 1 MB 不等；两者之间是**未加密的明文中段**（大图可达数 MB）。
- **闭环校验**：解密后明文的 MD5 与消息 XML 的 `<img md5>` 完全一致
  （实测 `bd3cf890…`、`5b11e459…`、`83e922b0…` 三例全中），这是判断"关联与解密都对"的最硬证据。
- 覆盖率（313 个 V2 文件样本）：**270 个直接解出完整 JPEG/PNG**，43 个是 WxAM（`wxgf`）原图；
  ChatTrace 对后者自动回退到同图缩略图，用户仍能看到这张图。

## 3. 语音转码现状

- `ffmpeg` **没有** SILK v3 解码器。
- `pilk` 为 **GPL-3.0**，未采用（避免许可传染）；ChatTrace 使用 BSD-3-Clause 的
  **silk-python（pysilk）** 在本地把 SILK v3 转成 WAV，界面与导出 HTML 里都是标准播放条（0.4.0 起）。
- 语音本体在已解密库的 `media_*.db` → `VoiceInfo.voice_data`，按 `chat_name_id + local_id` 关联。

## 4. 复现命令

```powershell
# 图片：解码单张旧式 dat（整文件 XOR 0xA4）
python -c "d=open(r'<...>_W.dat','rb').read(); open('out.jpg','wb').write(bytes(b^0xA4 for b in d))"

# 图片：解码单张 V2 dat（密钥 = md5(code + wxid)[:16]，XOR = code & 0xFF）
python -c "import hashlib,struct;from Cryptodome.Cipher import AES;from Cryptodome.Util import Padding;code=1234567;wxid='wxid_demo0000';k=hashlib.md5(f'{code}{wxid}').hexdigest()[:16].encode();d=open(r'<...>_t.dat','rb').read();_,a,x=struct.unpack_from('<6sLL',d);n=a+16-a%16;p=Padding.unpad(AES.new(k,AES.MODE_ECB).decrypt(d[15:15+n]),16);open('out.jpg','wb').write(p+d[15+n:len(d)-x]+bytes(b^(code&0xFF) for b in d[-x:]))"

# 语音：从已解密库导出某条语音
python -c "import sqlite3;c=sqlite3.connect(r'<dec>\message\media_0.db');b=c.execute('select voice_data from VoiceInfo where chat_name_id=? and local_id=?',(2,9302)).fetchone()[0];open('v.silk','wb').write(b)"
```
