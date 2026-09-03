# ChatTrace

完全本地的微信 4.x（4.1.11+）聊天数据工具链：自动取密钥 → 解密 → 浏览 → 导出。

## 能力（M1 + M2）

| 层 | 内容 |
| --- | --- |
| **KeyAgent** | Frida spawn 微信并捕获数据库主密钥（解决 4.1.11+ 旧式内存扫描失效）；HMAC 自检杜绝错误密钥 |
| **密钥保管** | 32B 主密钥仅以当前用户 **DPAPI** 密文落盘；界面只显示指纹；支持手动导入旧密钥 |
| **解密** | 全库增量解密（contact/session/message 分片/media/favorite…，24 库级别），每库独立 PBKDF2-SHA512-256000 派生密钥，解后 SQLite 冒烟；再次运行自动跳过新鲜文件 |
| **浏览** | 会话 / 联系人 / 单聊消息阅读（方向、群成员、图片语音占位、链接识别） |
| **导出** | 单会话全量导出 **txt / json / html**（自包含暗色网页视图） |
| **Web UI** | 引导式 5 步流程（选账号 → 密钥 → 解密 → 浏览 → 导出），全部数据在本机；零第三方前端依赖 |
| **分发** | PyInstaller 打包为免安装 exe；双击 → 自动开浏览器使用 |

## 快速开始（开发环境，Windows + 微信 4.1.11+）

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"

# 自检（frida / 微信 / 锚点 / 密钥目录）
chattrace doctor

# 引导式 Web UI（默认打开 http://127.0.0.1:8714）
chattrace webui
```

### 命令行（等价能力）

```powershell
# 1) 密钥：手动导入并 HMAC 自检
chattrace key store <64-hex> --account-dir "D:\...\xwechat_files\wxid_xxx"
chattrace key test  --account-dir "D:\...\xwechat_files\wxid_xxx"
#   或自动抓取（微信先正常登录→托盘退出；会自动拉起并等待登录）
chattrace keyagent run --store --account-dir "D:\...\xwechat_files\wxid_xxx"

# 2) 解密（增量，重复运行只补新数据）
chattrace data status --account-dir "D:\...\xwechat_files\wxid_xxx"
chattrace data decrypt --account-dir "D:\...\xwechat_files\wxid_xxx"

# 3) 浏览
chattrace chat list     --account-dir "D:\...\xwechat_files\wxid_xxx"
chattrace chat read     --account-dir "D:\...\xwechat_files\wxid_xxx" wxid_好友 --limit 30
chattrace chat contacts --account-dir "D:\...\xwechat_files\wxid_xxx" --query 某名

# 4) 导出（txt / json / html）
chattrace export --account-dir "D:\...\xwechat_files\wxid_xxx" `
  --user wxid_好友 --format html
```

## 打包分发（M2）

```powershell
.\.venv\Scripts\python -m pip install pyinstaller
.\.venv\Scripts\python -m PyInstaller --noconfirm --clean --onedir --console --name ChatTrace `
  --add-data "src\chattrace\webui\static;chattrace\webui\static" `
  --collect-submodules chattrace `
  --hidden-import chattrace.cli --hidden-import chattrace.webui.server `
  scripts\chattrace_launcher.py
# 产物：dist\ChatTrace\ChatTrace.exe —— 双击即用（或压缩该目录为 zip 分发）
```

数据目录：解密明文副本与导出文件均在
`%LOCALAPPDATA%\ChatTrace\accounts\<wxid>\`（`decrypted/` 与 `exports/`）。
密钥在 `%LOCALAPPDATA%\ChatTrace\keys\`（DPAPI 密文）。

## 开源与合规

- 本项目基于 **Frida** 动态插桩方案；参考来源与格式原理见 [REFERENCES.md](REFERENCES.md)，
  第三方依赖与各许可声明见 [NOTICE.md](NOTICE.md)。
- 以 **MIT License** 开源（见 [LICENSE](LICENSE)）。
- 仅用于导出**本人账号、本机**的聊天数据；非官方工具，与腾讯/微信无任何关联，
  不包含微信专有代码，无云端或网络上报能力。请勿用于他人账号或未授权数据。
