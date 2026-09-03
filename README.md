# ChatTrace

完全本地的微信 4.x（4.1.11+）聊天数据工具链。核心能力：

- **KeyAgent**：Frida spawn 抓取微信数据库主密钥（解决 4.1.11+ 旧式内存扫描失效问题）
- **HMAC 自检**：密钥抓取/导入后立即对目标库校验，杜绝过渡态/错误密钥
- **DPAPI 密钥存储**：密钥仅以当前用户 DPAPI 密文落盘，界面只显指纹
- **计划**（见 `../wechat-export-toolchain-plan.md`）：解密 → 会话浏览 → txt/json/html 导出

## 快速开始（M1：KeyAgent）

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"

# 环境自检
chattrace keyagent doctor

# 手动导入已知密钥（hex）并立即对指定账号库做 HMAC 自检
chattrace key store <64-hex> --account-dir "D:\...\xwechat_files\wxid_xxx"
chattrace key test  --account-dir "D:\...\xwechat_files\wxid_xxx"

# 自动抓取（微信需处于可自动登录状态；异常退出后先正常开→托盘退一次）
chattrace keyagent run --account-dir "D:\...\xwechat_files\wxid_xxx"

# 锚点自动定位 / 版本登记
chattrace keyagent locate --weixin-dll "C:\Program Files\Weixin\4.1.12.55\Weixin.dll"

# 查看 / 删除密钥
chattrace key status
chattrace key forget --account-dir "D:\...\xwechat_files\wxid_xxx"
```

## 合规

仅用于导出**本人账号、本机**的聊天数据；不包含云端或共享能力。
