#!/usr/bin/env python3
"""Cold/warm launch through real ssh Match exec, without touching the user's agent or SSH config."""
import pathlib
import plistlib
import shutil
import subprocess
import tempfile
import time
import uuid
import os
import signal

root = pathlib.Path(__file__).resolve().parent
subprocess.run(["swift", "build", "--package-path", str(root)], check=True)
binary = pathlib.Path(subprocess.check_output(["swift", "build", "--package-path", str(root), "--show-bin-path"], text=True).strip()) / "bwssh"
with tempfile.TemporaryDirectory(prefix="bwssh-smoke-", dir="/tmp") as directory:
    folder = pathlib.Path(directory)
    app = folder / "bwssh Smoke.app"  # Spaces also exercise shell and SSH config quoting.
    executable = app / "Contents/MacOS/bwssh"
    executable.parent.mkdir(parents=True)
    shutil.copy2(binary, executable)
    info = plistlib.loads((root / "Resources/Info.plist").read_bytes())
    info.update(CFBundleIdentifier="com.bwssh.smoke." + uuid.uuid4().hex, BWSSHSmokeSocket=str(folder / "agent.sock"))
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
    subprocess.run(["codesign", "--force", "--sign", "-", str(app)], check=True)
    config = folder / "ssh_config"
    config.write_bytes(subprocess.check_output([str(executable), "--smoke-config"]))
    probe = ["/usr/bin/ssh", "-G", "-F", str(config), "probe"]
    try:
        started = time.monotonic()
        output = subprocess.check_output(probe, text=True, stderr=subprocess.PIPE, timeout=20)
        elapsed = time.monotonic() - started
        assert "identityagent " + str(folder / "agent.sock") in output
        for _ in range(50):
            if (folder / "pid").exists():
                break
            time.sleep(0.02)
        assert (folder / "agent.sock").exists() and (folder / "pid").exists(), "SSH did not start the agent"
        pid = int((folder / "pid").read_text())
        subprocess.run(probe, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=15)
        assert int((folder / "pid").read_text()) == pid, "Warm launch started a second process"
        result = subprocess.run(["/usr/bin/ssh-add", "-L"], env={**os.environ, "SSH_AUTH_SOCK": str(folder / "agent.sock")}, text=True, capture_output=True, timeout=10)
        assert result.returncode == 1 and "no identities" in result.stdout.lower() + result.stderr.lower(), result
        print(f"PASS: ssh Match exec cold launch ({elapsed:.2f}s), warm reuse, and real ssh-add socket request")
    finally:
        if (folder / "pid").exists():
            try:
                os.kill(int((folder / "pid").read_text()), signal.SIGTERM)
            except ProcessLookupError:
                pass
