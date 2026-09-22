# bwssh

[中文](README.md)

bwssh is a native Windows (WinUI 3) SSH agent. It reads SSH keys from your Bitwarden vault and serves them to `ssh`, `git`, and AI agents such as Claude Code.

It works with **official Bitwarden accounts** (bitwarden.com / bitwarden.eu) and with accounts on **self-hosted servers**.

## Features

- **SSH agent**: listens on `\\.\pipe\openssh-ssh-agent`, so the built-in Windows OpenSSH tools (`ssh`, `scp`, `sftp`, `ssh-add`, `ssh-keygen`) work out of the box. Supports Ed25519, RSA, and ECDSA (P-256/384/521) keys, plus Git SSH commit signing.
- **Native notification approvals**: when a program uses a key, a Windows notification appears in the bottom-right corner. It shows the process chain (for example `claude.exe → bash.exe → git.exe → ssh.exe`), the destination host, and the key name, and you can approve or deny right there.
- **Three approval modes**
  - Always ask
  - Remember until lock: ask once per key and host
  - Never ask: allow while the vault is unlocked
- **Time-limited approval per program**: choose "Allow 15 min" in the notification, and that program (for example, the current Claude Code session) can use the key without asking for 15 minutes. The duration is configurable.
- **Audit log**: records the time, process chain, destination, key, and result of every signing request.
- **Quick unlock**: Windows Hello and PIN. When a request arrives while the vault is locked, you can unlock with Windows Hello and approve directly from the notification.
- **Auto-lock and sync**: lock when idle, when Windows locks, or on sleep, and sync the vault on a schedule.
- **Key management**: generate new keys (Ed25519 / RSA), import existing private keys (OpenSSH, PKCS#8, PEM, including passphrase-protected ones), and rename keys or move them to the trash.
- **Start with Windows**: runs quietly in the tray and uses few resources.
- **English and Chinese UI**: follows the Windows display language.

## Install

Download `bwssh-setup-x.y.z.exe` from [Releases](https://github.com/luoxiaoxin123/bwssh/releases) and run it. No administrator rights are needed.

Requirements: Windows 10 2004 (19041) or later, x64. The installer is not code-signed, so SmartScreen may warn on first run. Choose "More info → Run anyway".

## Getting started

1. Open bwssh and pick a server: bitwarden.com, bitwarden.eu, or a self-hosted server (enter its URL, e.g. `https://vault.example.com`). Then sign in with your email and master password. Two-step login (authenticator app, email, YubiKey OTP) and API key sign-in are supported.
2. Check that your terminal sees the keys:

   ```powershell
   ssh-add -L
   ```

3. If you use Git for Windows, make Git use the built-in Windows OpenSSH. The ssh bundled with Git for Windows cannot use Windows named pipes:

   ```powershell
   git config --global core.sshCommand "C:/Windows/System32/OpenSSH/ssh.exe"
   ```

4. From now on, `ssh`, `git push`, and `git commit -S` trigger an approval notification whenever they need a key.

The Diagnostics page checks the pipe, conflicting programs, and your Git configuration, and includes a one-click connection test.

## Using it with Claude Code and other agents

When an agent runs `git push`, `ssh`, and similar commands, you get the same approval notification. It shows which agent started the request, for example `claude.exe → bash.exe → git.exe → ssh.exe`.

- To let an agent run several git operations in a row, choose "Allow 15 min". That agent process can then use the key without asking. A different agent process, a different key, or locking the vault asks again.
- Allowed programs are listed on the SSH keys page, where you can revoke them at any time. The tray menu also has "Revoke all temporary approvals".
- Every request is written to the audit log.

## Notes

- **Pipe conflicts**: only one program can own `\\.\pipe\openssh-ssh-agent` at a time.
  - If the Windows OpenSSH Authentication Agent service is running, run this in an elevated PowerShell:

    ```powershell
    Stop-Service ssh-agent; Set-Service ssh-agent -StartupType Disabled
    ```

  - If the Bitwarden desktop app has its SSH agent turned on, turn it off in that app's settings.
  - Once the pipe is free, bwssh takes it over within 5 seconds.
- **Not supported**: SSO sign-in; Duo and WebAuthn two-step login; accounts that use the new COSE encryption format; PuTTY `.ppk` keys (export them to OpenSSH format with PuTTYgen first).

## Data and security

- Local data lives in `%LOCALAPPDATA%\BwSshAgent`.
  - Synced vault data stays encrypted and is additionally protected with Windows DPAPI, so only the current Windows user can read it.
  - Tokens, the public key list, and PIN settings are also protected with DPAPI.
- Private keys are decrypted only while the vault is unlocked, kept in memory, and zeroed on lock.
- Vault writes (create, rename, move to trash) are encrypted locally before upload. The server only receives ciphertext.
- The PIN protects the user key with an Argon2id-derived key. By default, you must unlock once with your master password or Windows Hello after each start before the PIN works. Five wrong PINs in a row remove the PIN.
- Windows Hello unlock has a Hello-protected key sign a fixed challenge, and derives the encryption key from that signature.
- The named pipe accepts connections from the current user only.

## Building from source

Requires the .NET 10 SDK. Building the installer also requires [Inno Setup 6](https://jrsoftware.org/isinfo.php).

```powershell
dotnet test --project tests/BwSshAgent.Core.Tests   # run the tests
./build.ps1 -Version 1.0.0                           # writes artifacts/installer/bwssh-setup-1.0.0.exe
```

When you publish a new GitHub Release, the [workflow](.github/workflows/release.yml) runs the tests, builds the installer, and attaches it to that release.

## License

[Apache License 2.0](LICENSE)
