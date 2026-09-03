# 参考来源 References

ChatTrace 基于 **Frida** 动态插桩方案解决微信 4.1.11+（SQLCipher 4）数据库
主密钥获取问题，并参考下列公开项目与资料（详见 [NOTICE.md](NOTICE.md) 的许可说明）。

## 核心技术路线

- **Frida**（动态插桩框架）：注入微信进程、Hook 编解码配置函数、拦截内存中的
  32 字节数据库主密钥。
  https://github.com/frida/frida · https://frida.re

## 直接参考项目

- **wechat-chatlog-studio**（MIT，mordekasiser）
  本地 Windows 微信桌面聊天浏览/导出工具。ChatTrace 的账号目录发现
  （`xwechat_files/<wxid>/db_storage/message/message_0.db`）、
  `contact` / `SessionTable` / `Msg_<md5(username)>` / `Name2Id` 数据库语义，
  以及消息类型的占位渲染（图片/语音/视频/链接）等公开方法与其对齐。
  https://github.com/mordekasiser/wechat-chatlog-studio

## 格式与原理资料

- **SQLCipher**（Zetetic LLC）：WCDB/SQLCipher 4 加密格式 —— 文件头 salt、
  PBKDF2-HMAC-SHA512 密钥派生、页级 AES-CBC、每页 IV 与 reserve 布局。
  https://www.zetetic.net/sqlcipher/ · https://github.com/sqlcipher/sqlcipher
- **WCDB**（WeChat Database，腾讯开源）：移动端 SQLCipher 封装与 KeyDerivation，
  帮助理解密钥派生参数与 page 布局的社区实现。
  https://github.com/Tencent/wcdb

## 构建与分发

- **PyInstaller**：https://github.com/pyinstaller/pyinstaller
- **pycryptodomex**：https://github.com/Legrandin/pycryptodome

## 免责声明

ChatTrace 是独立、非官方的个人工具，与腾讯/微信无任何关联；仅用于导出
**本人账号、本机**的聊天数据。所有密钥与数据均保存在本机。
