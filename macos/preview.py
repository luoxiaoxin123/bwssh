#!/usr/bin/env python3
"""Build a separate debug-only UI preview with synthetic keys and no agent listener."""
import pathlib
import hashlib
import plistlib
import shutil
import subprocess
import argparse
import os

parser = argparse.ArgumentParser()
parser.add_argument("--state", choices=["login", "locked", "unlocked", "approval-pin", "approval-password", "update"], default="unlocked")
parser.add_argument("--screenshot", type=pathlib.Path)
parser.add_argument("--appearance", choices=["light", "dark"], default="dark")
args = parser.parse_args()

root = pathlib.Path(__file__).resolve().parent
subprocess.run(["swift", "build", "--package-path", str(root)], check=True)
binary = pathlib.Path(subprocess.check_output(["swift", "build", "--package-path", str(root), "--show-bin-path"], text=True).strip()) / "bwssh"
fingerprint = hashlib.sha256(binary.read_bytes()).hexdigest()[:8]
app = root.parent / ("artifacts/macos/bwssh Preview-" + fingerprint + "-" + args.state + ".app")
(app / "Contents/MacOS").mkdir(parents=True, exist_ok=True)
shutil.copy2(binary, app / "Contents/MacOS/bwssh")
info = plistlib.loads((root / "Resources/Info.plist").read_bytes())
info.update(CFBundleIdentifier="com.bwssh.preview." + fingerprint + "." + args.state, CFBundleName="bwssh Preview", CFBundleDisplayName="bwssh Preview", LSEnvironment={"BWSSH_UI_PREVIEW": "1", "BWSSH_UI_PREVIEW_STATE": args.state})
(app / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
subprocess.run(["codesign", "--force", "--sign", "-", str(app)], check=True)
print(app, flush=True)
if args.screenshot:
    screenshot = args.screenshot.resolve()
    screenshot.parent.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    environment.update(info["LSEnvironment"])
    environment.update(BWSSH_PREVIEW_SCREENSHOT=str(screenshot), BWSSH_PREVIEW_APPEARANCE=args.appearance)
    subprocess.run([str(app / "Contents/MacOS/bwssh"), "-AppleLanguages", "(zh-Hans)", "-AppleLocale", "zh_CN"], env=environment, check=True, timeout=30)
    if not screenshot.is_file():
        raise RuntimeError("Preview did not produce the screenshot")
    print(screenshot)
