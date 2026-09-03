# ChatTrace 0.2.0 (M2)

完全本地的微信 4.x（4.1.11+）聊天数据工具链，基于 **Frida** 动态插桩方案。

## 功能
- **KeyAgent**：Frida 自动捕获微信数据库主密钥（解决 4.1.11+ 旧式内存扫描失效），HMAC 自检 + DPAPI 本机加密保管
- **全库解密**：contact/session/message 分片/media/favorite 等 24 库级别增量解密（每库独立 PBKDF2-SHA512-256000），SQLite 冒烟校验
- **浏览**：会话 / 联系人 / 单聊消息（方向、群成员、图片/语音占位、链接识别）
- **导出**：单会话全量 txt / json / html（自包含暗色网页视图）
- **Web UI**：引导式 5 步流程（选账号 → 密钥 → 解密 → 浏览 → 导出），全数据本机处理，双击 `ChatTrace.exe` 即用

## 使用
解压 zip → 双击 `ChatTrace.exe` → 浏览器自动打开 `http://127.0.0.1:8714`，按引导操作。
（首次自动获取密钥需先正常登录微信一次并从托盘退出。）

## 系统要求
- Windows 10/11，微信 4.1.11+（含已登录账号数据，`xwechat_files` 目录）

## SHA-256
`9ddd23f9c96e0f94c1f5d1276bcd326d67680309192729845d0a8d9e6aa816bf`

## 许可与合规
- MIT License · Copyright (c) 2026 Qiao Xinliang (qiaodogbear)
- 仅用于导出本人账号、本机聊天数据；非官方工具，与腾讯/微信无关联；无云端/网络上报
- 第三方依赖与参考来源见仓库内 `NOTICE.md` / `REFERENCES.md`
