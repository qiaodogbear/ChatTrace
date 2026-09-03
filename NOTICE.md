# 第三方依赖与合规声明 (Third-Party Notices)

ChatTrace 以 **MIT License** 开源（见 [LICENSE](LICENSE)）。本仓库自身代码均为
独立编写；运行时依赖与参考项目分别受其各自许可约束，声明如下。

## 运行时依赖（PyInstaller 产物中再分发）

| 组件 | 用途 | 许可 | 上游 |
| --- | --- | --- | --- |
| **frida / frida-tools** | 附加到本机 WeChat 进程、注入 KeyAgent 脚本捕获内存密钥 | frida 核心 **LGPL-2.1-or-later**；frida python 绑定 **MIT** | https://github.com/frida/frida |
| **pycryptodomex** | AES-CBC / PBKDF2 解密微信 SQLCipher 数据库 | 公有领域 (Public Domain) + BSD-2-Clause | https://github.com/Legrandin/pycryptodome |
| **PyInstaller**（仅构建期） | 打包为免安装 exe | GPL-2.0-or-later（含 bootloader 例外条款） | https://github.com/pyinstaller/pyinstaller |

- **frida（LGPL-2.1）**：ChatTrace 将其作为独立、未修改的第三方组件随发行包分发。
  LGPL 允许在动态/独立使用下分发二进制；如您进一步再分发本发行包，请随附
  frida 的 LGPL-2.1 许可文本，并可于上述上游获取其对应源码（本发行包不包含对
  frida 的任何修改）。
- **pycryptodomex**：版权所有者已将该库贡献至公有领域并按 BSD 双许可发布。
- **PyInstaller 产物**：PyInstaller 的 bootloader 例外使打包产物不受 GPL 传染。

## 参考实现与致谢（参考其公开方法/数据库语义，本仓库代码独立编写）

| 参考来源 | 关系 | 许可 |
| --- | --- | --- |
| **wechat-chatlog-studio**（mordekasiser）—— 本地微信桌面聊天浏览/导出工具 | 账号目录布局、contact/SessionTable/Msg_<md5> 查询语义、消息类型渲染思路参考 | MIT |
| **SQLCipher** (Zetetic) | 数据库加密格式原理（PBKDF2 派生、页级 AES、reserve 布局）依据其公开格式说明理解 | BSD 风格 |
| **Frida** 官方文档与示例 | KeyAgent 注入与脚本基础设施 | LGPL-2.1 / Apache-2.0 (docs) |
| **WeChatDaily**（Bryan-Cyf） | M3 媒体：SILK 语音链路与 macOS 图片 key 思路的**格式确认**（macOS 公式不适用于 Windows，代码未采用） | MIT |
| **xlight/chatlog** | M3 媒体：4.x 图片容器三态与"视频明文"的行为佐证 | Apache-2.0 |

> M3 图片 dat 解密（单字节 XOR 反推等）由 ChatTrace 依据文件头与
> JPEG/PNG/GIF 魔数**独立推导并在真实数据上验证**，未包含上述参考项目代码。

## 法律与合规提醒

- ChatTrace **仅用于导出本人账号、本机**的聊天数据；请勿用于他人账号、未授权数据
  或任何违反当地法律/平台条款的用途。
- ChatTrace 与腾讯公司、微信及其附属产品**无任何关联**，非官方工具。
- 微信应用本身、其数据库格式与加密方案属于腾讯公司的知识产权；本项目不包含任何
  微信专有代码或资源，仅在本机对自有数据进行格式互操作。
- 数据与密钥均保存在本机（`%LOCALAPPDATA%\ChatTrace\`）；项目不提供任何云端或
  网络同步能力，无遥测、无联网上报。
- 逆向研究存在平台条款与法律风险（社区已出现因腾讯函件要求删库的先例）。本项目
  仅用于个人数据归档与研究；请自行评估风险并遵守适用法律。

> 若您是某参考项目的作者并认为致谢或引用不准确，欢迎通过 GitHub Issue 指出。
