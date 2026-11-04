# macOS 开发说明

安装、登录、SSH 配置、Touch ID 和 PIN 的使用方法已合并到[项目 README](../README.md)。
本文只介绍构建和调试。英文使用说明见 [English README](../README.en.md)。

## 从源码构建

原生 Swift / SwiftUI / AppKit 应用，最低 macOS 13，运行时不需要 .NET、Electron、WebView 或 Bitwarden CLI。

安装 Xcode 后，在仓库根目录执行：

```sh
swift test --package-path macos
python3 macos/package.py --arch arm64 --version 1.0.5
# Intel Mac 使用 --arch x86_64
```

输出目录为 `artifacts/macos/<arch>/`，包含应用、ZIP、DMG 和 `SHA256SUMS`。
打包脚本使用临时签名，不包含 Developer ID 签名和 Apple 公证。

[macOS GitHub Actions](../.github/workflows/macos.yml) 分别在 ARM 和 Intel runner 上运行测试、检查按需启动、构建安装包，并校验签名和架构。上传的包默认保留 30 天。

## 本地验证

只有 Command Line Tools、没有 Xcode / XCTest 时，可以运行同一套核心测试：

```sh
python3 macos/check-local.py
```

测试使用临时密码库和密钥，覆盖登录、加密、密钥导入、SSH 签名、主机绑定、审批、PIN 重启策略、配置备份和本地存储。OpenSSH 互操作测试通过真实 socket 调用系统 `ssh-add` 和 `ssh-keygen`，检查五种密钥的签名和验签。

按需启动可单独检查：

```sh
python3 macos/check-on-demand.py
```

它让系统 SSH 读取临时配置，启动隔离的测试应用、等待 socket，并检查后续请求能否复用已有进程。不会读取个人账号、修改 `~/.ssh/config`，也不会停止正在使用的 agent。测试入口只存在于 Debug 构建。

Touch ID、通知权限、登录项和锁屏行为仍需在实际设备上检查。

## 界面预览

```sh
python3 macos/preview.py --state locked
# 也支持 --state login、unlocked、approval-pin、approval-password
```

审批预览中的虚构 PIN 为 `123456`。

生成独立的 Debug 预览应用，使用虚构账号和临时密钥，不读取个人密码库，不启动 agent、通知或定时同步。预览菜单可切换浅色、深色和窄窗口。预览入口不会出现在发布包中。

## 代码与存储

- `Sources/bwssh`：SwiftUI 界面、AppKit 窗口与菜单栏、系统通知。
- `Sources/BwCore`：Bitwarden API、密码库解密、SSH agent 协议、审批和本地存储。
- `Sources/CBwCrypto`：Argon2 和 OpenSSH bcrypt 支持。来源与许可证见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
- 本地数据位于 `~/Library/Application Support/bwssh`，目录权限为 0700，文件和 socket 为 0600。数据使用 AES-GCM 加密，存储密钥保存在钥匙串中。
- 私钥在锁定时释放，应用持有的私密缓冲区会清零；Swift 和系统框架可能保留临时副本，不能保证所有底层副本立即清零。
- PIN 重启策略默认要求先用主密码或 Touch ID 解锁。旧设置文件缺少新选项时仍沿用此默认值；关闭选项后允许直接使用 PIN，错误次数会持久保存。

SSH 使用 `IdentityAgent` 选择 bwssh；`ssh-add` 和 Git SSH 提交签名使用 `SSH_AUTH_SOCK`。后两者不读取 SSH 配置，所以不会触发 `Match exec` 按需启动。已建立的 SSH ControlMaster 连接也可能直接复用，不再请求签名。

没有有效主机绑定的请求不会缓存“锁定前记住”的决定，转发请求不提供程序临时授权。
自建服务器要求 HTTPS；目前不支持 SSO、Duo / WebAuthn、COSE/type 7、PuTTY `.ppk` 或 RSA SHA-1 签名。macOS 的 Unix socket 路径长度限制为 103 字节。
