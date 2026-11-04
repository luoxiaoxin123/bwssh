# bwssh for macOS

原生 Swift / SwiftUI / AppKit 菜单栏 SSH agent，最低 macOS 13。
支持 Apple Silicon (`arm64`) 和 Intel (`x86_64`)；运行时不需要 .NET、Electron、WebView 或 Bitwarden CLI。
Windows 版本继续使用仓库根目录的解决方案；macOS 版本是独立原生实现。

## 1.0.3 通知审批与解锁

- 移除「刷新解锁信息」按钮；缓存解密失败时自动尝试一次在线刷新并用本次密码重试，成功后保存修复值。正常离线解锁不受影响。
- 默认仅发送 macOS 系统通知，不再同时弹出审批窗口；前台运行时也显示通知。
- 通知提供批准、按设置时长临时放行、拒绝；转发请求不提供临时放行。系统可能将操作收进通知的选项菜单。
- 主动关闭通知按拒绝处理；超时、取消或锁定后撤回通知，过期操作不再生效。
- 点击通知或菜单栏的「待审批请求」可查看详情；密码库锁定时可通过 Touch ID 或紧凑窗口解锁。
- 首次启动请允许通知；通知权限被关闭或发送失败时，才回退到紧凑审批窗口并提示开启通知。

## 1.0.2 修复

- 首次启动显示登录页；已有账号但密码库锁定时显示独立解锁页，验证成功后才进入主界面。
  锁定会隐藏密钥列表、审计和设置窗口。SSH agent 的锁定状态仍拒绝签名。
- 密码输入框支持右侧小眼睛显示 / 隐藏；临时授权时长、审批等待时间、空闲锁定和同步间隔均可直接输入整数，非法值不保存。
- 登录、设置、连接页使用统一背景，修复深色模式下窄表单与两侧背景的色差。
- 账户解锁信息以“加密用户密钥 + KDF + 盐值”整体解析，兼容新版 `masterKeyWrappedUserKey` 字段；
  旧缓存解锁时优先使用快照内的完整参数，成功后保存修复值。不会跳过 MAC 校验。
  若仍无法解锁，可重新登录；不必删除个人密钥。

## 1.0.1 界面更新

采用 AppKit 标准窗口工具栏和搜索控件，密钥与审计使用紧凑表格，固定详情区避免选中行时窗口跳动。
设置改为独立窗口（`⌘,`），支持 `⌘N` 添加密钥、`⌘R` 同步、`⌘F` 搜索和 `⌘W` 关闭窗口。
不支持 Touch ID 的设备直接显示不可用。界面使用系统语义颜色，已用合成数据检查浅色、深色及窄窗口布局。

设计参考 Apple 的 [macOS 设计指南](https://developer.apple.com/design/human-interface-guidelines/designing-for-macos)、
[工具栏](https://developer.apple.com/design/human-interface-guidelines/toolbars)和
[侧边栏](https://developer.apple.com/design/human-interface-guidelines/sidebars)。这不是 Apple 的认证或逐条合规声明。

## 安装和使用

1. 从分支的 **macOS native packages** Actions 运行中下载对应架构的 artifact。
   每份 artifact 包含 `.dmg`、`.zip` 和 `SHA256SUMS`。M 系列选 `arm64`，Intel 选 `x86_64`。
2. 打开 DMG，将 `bwssh.app` 拖入 Applications，再打开应用。
   当前包使用本机临时签名，没有 Developer ID 签名和 Apple 公证；首次打开可能需在系统设置
   → 隐私与安全性中选择「仍要打开」。更新后钥匙串可能重新请求访问授权。
3. 登录 bitwarden.com、bitwarden.eu 或 HTTPS 自托管服务器。
   支持主密码、验证器 / 邮件 / YubiKey OTP、API Key，以及新设备邮件验证码。
   API Key 登录仍需主密码在本机解密密码库。
4. 在「诊断」中点击「配置 SSH」，将固定 socket 写入 `~/.ssh/config`。
   修改前备份为 `~/.ssh/config.bwssh.bak`，不会覆盖已有备份。撤销仅删除 bwssh 管理的区块。
5. 将诊断页显示的 export 加到 `~/.zshrc`（其他 shell 用对应配置），并在当前终端执行它：

   ```sh
   export SSH_AUTH_SOCK="$HOME/Library/Application Support/bwssh/agent.sock"
   ssh-add -L
   ```

SSH / Git 登录使用 `IdentityAgent`；`ssh-add` 和 Git SSH 提交签名使用 `SSH_AUTH_SOCK`。
例如配置 Git SSH 签名：

```sh
git config --global gpg.format ssh
# 粘贴 bwssh 复制的公钥，不要填私钥。
git config --global user.signingkey 'ssh-ed25519 AAAA...'
git config --global commit.gpgsign true
```

系统通知显示密钥、程序链、操作和可用目标；点击通知可在紧凑窗口查看完整指纹。
命令行推断的主机与通过 `session-bind@openssh.com` 验证的主机指纹分别标明。
不带有效主机绑定的认证请求不缓存「锁定前记住」决定；仍可逐次批准。

## Windows 功能对应

| 功能 | macOS 实现 |
| --- | --- |
| SSH agent / Git SSH 签名 | Unix socket；Ed25519、RSA SHA-256/512、ECDSA P-256/384/521 |
| 通知审批 | 默认 UserNotifications；通知不可用时回退紧凑窗口 |
| 每次询问 / 锁定前记住 / 从不询问 | 设置页；锁定、退出账号、同步、手动撤销会清除缓存 |
| 按程序限时放行 | 按密钥、PID、进程启动时间及路径绑定；转发请求不匹配程序授权 |
| 程序链 / 审计 | 内核提供连接方 PID 和祖先进程；本地加密存储最近 2000 条，可筛选、清空 |
| Windows Hello | Touch ID；钥匙串使用当前生物识别集合访问控制 |
| PIN | Argon2id；连续失败 5 次清除；每次启动后先主密码 / Touch ID 解锁一次 |
| 空闲 / 锁屏 / 睡眠自动锁定 | 原生系统事件与空闲计时；间隔在设置页调整 |
| 定时同步 | URLSession 直连 Bitwarden；失败后退避重试 |
| 生成、导入、复制公钥、改名、回收站 | 支持；生成 Ed25519 / RSA 3072，写入前在本机加密 |
| OpenSSH / PEM / PKCS#8 导入 | 支持；OpenSSH bcrypt + AES-256-CTR/CBC；加密 PKCS#8 使用 PBES2/PBKDF2/AES-CBC |
| 常驻托盘 / 开机启动 | 菜单栏 / macOS 登录项；关闭窗口后 agent 继续运行 |
| 按需启动 | 诊断页设置 `Match exec`，启动原生 app 后等待 socket；移动 app 后重新设置 |
| 中英文 | 跟随系统首选语言 |

按需启动遵循 Windows 版同样的限制：`ssh-add` 和 `git commit -S` 不读取 SSH 配置，须先打开应用。
更改 `SSH_AUTH_SOCK` 只影响当前终端及其子进程，已打开的其他终端或 IDE 需要更新环境后再使用。
可以与系统 ssh-agent 共存，但一个客户端一次只会选择一个 `IdentityAgent` / `SSH_AUTH_SOCK`。

## 数据和边界

- 本机数据：`~/Library/Application Support/bwssh`（目录 0700，socket / 文件 0600）。
- 同步快照保留 Bitwarden 密文，账户令牌、公钥缓存、PIN 包装和审计再用 AES-GCM 加密，
  存储密钥保存在当前用户的钥匙串。文件名也参与认证，不能交换文件绕过校验。
- 主密码不落盘；解锁后的私钥只在内存中。锁定释放 Security.framework 密钥，清零应用拥有的
  私密缓冲区。Swift String、Data 和系统加密框架可能产生临时副本，不能承诺所有底层副本立即清零。
- 不支持 SSO、Duo / WebAuthn 两步验证、COSE/type 7、PuTTY `.ppk`，也不启用 RSA SHA-1 签名。
- 自托管服务器目前要求 HTTPS；Unix socket 路径受 macOS 的 103 字节长度限制，超长用户目录会报错。
- CI 与本地自动测试使用合成密码库和临时密钥，不访问个人账户。
  实际 Bitwarden / Vaultwarden 账户登录、Touch ID、系统通知权限、登录项和锁屏行为仍需在目标机器验收。
- 原生实现去掉了跨平台运行时，但实际常驻内存取决于窗口、密钥数量、系统版本和 KDF 参数。
  Argon2id 在解锁期间会按账户设定临时分配内存，不能将这段峰值当作常驻占用。

## 构建与验证

完整 Xcode 环境：

```sh
swift test --package-path macos
python3 macos/package.py --arch arm64 --version 1.0.3
python3 macos/package.py --arch x86_64 --version 1.0.3
```

仅安装 Command Line Tools、没有 XCTest 的机器可运行同一套核心用例：

```sh
python3 macos/check-local.py
```

测试覆盖 Bitwarden PBKDF2/HKDF 与 Argon2id 向量、密文篡改、密钥导入、主机绑定、审批模式、
锁定清除授权、取消、加密存储和 SSH 配置备份逻辑。系统 `ssh-add` 列出密钥并测试签名；
`ssh-keygen -Y sign/verify` 通过真实 socket 完成五种密钥的 Git 命名空间签名和独立验签。

输出目录为 `artifacts/macos/<arch>/`。GitHub Actions 分别在原生 ARM 和 Intel runner 上测试、
构建、检查签名与架构，上传各自的 ZIP、DMG 和 SHA256SUMS，默认保留 30 天。

第三方源码来源及许可证见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 界面开发预览

`python3 macos/preview.py --state locked`（也支持 `login` / `unlocked`）生成独立的 Debug 预览 app，使用虚构账号和临时密钥，不启动 agent socket、
通知或定时同步，也不读取个人密码库。预览菜单可切换浅色、深色和窄窗口。预览入口仅编译到 Debug，
不会出现在发布包中。

## macOS SSH 配置与按需启动

macOS 自带 OpenSSH 支持 Unix socket。无需改用其他 SSH 程序或关闭系统 ssh-agent，
在「连接与诊断」设置 `IdentityAgent` 即可让 SSH 连接选用 bwssh。按需启动的「设置」同时写入
`IdentityAgent` 与 `Match exec`，因此无需重复点一次「配置 SSH」。

`ssh-add` 和 Git 的 SSH 提交签名通过 `SSH_AUTH_SOCK` 选择 agent，仍需按上文设置 shell 环境。
它们不会读取 SSH 配置，故 `Match exec` 不会为它们启动应用。已建立的 SSH ControlMaster 连接也可能复用现有连接而不再请求签名。

可运行 `python3 macos/check-on-demand.py` 验证真实系统 SSH 读取临时配置、冷启动一个隔离的测试 app、
等待 socket、重复请求复用进程，再用系统 ssh-add 请求该 socket。测试不读取个人账户、不会修改
`~/.ssh/config`，也不停止已有 agent；测试入口仅存在于 Debug。CI 在两个架构上都运行该检查。
