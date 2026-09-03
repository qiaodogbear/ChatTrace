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

## 媒体（图片/语音/视频）解密研究（M3）

ChatTrace M3 的图片 dat 解密与媒体关联为**独立实现的算法**，但下列公开资料
用于确认格式、解密判定与关联字段（均仅作参考核对，代码未照搬；许可见 NOTICE.md）：

- **Bryan-Cyf/WeChatDaily**（MIT）：macOS 4.x 图片 key 派生思路、
  `VoiceInfo` SILK 语音链路（`.silk` → PCM → 转码）。
  https://github.com/Bryan-Cyf/WeChatDaily
  （其 `find_image_key_macos.py` 的 macOS 派生公式**不适用于** Windows，仅供参考）
- **xlight/chatlog**（Apache-2.0）：4.x 媒体目录组织、图片三态
  （纯 XOR / V1 / V2 容器头 `07 08 56 3x 08 07`）与"视频为明文、仅图片加密"
  的行为佐证。https://github.com/xlight/chatlog
- 社区文章《微信 4.x .dat 格式图片解密（含 WxAM）》（CSDN）：
  https://blog.csdn.net/weixin_39441881/article/details/157291104
- **kn007/silk-v3-decoder**（MIT）：SILK v3 解码参考（语音转码可选项）。
  https://github.com/kn007/silk-v3-decoder
- 注意：macOS 派生算法的来源 WeFlow 采用 CC BY-NC-SA 4.0（非商业），
  本工具未参考其代码；sjzar/chatlog 曾因腾讯函件删库 —— 本工具的图片解密
  公式均由我们自己从样本验证得出（单字节 XOR 由文件头与 JPEG/PNG 魔数反推），
  不包含上述仓库的代码。

## 免责声明

ChatTrace 是独立、非官方的个人工具，与腾讯/微信无任何关联；仅用于导出
**本人账号、本机**的聊天数据。所有密钥与数据均保存在本机。
