#!/usr/bin/env python3
"""Build a native, ad-hoc-signed app, ZIP and DMG. No third-party build dependencies."""
import argparse
import hashlib
import pathlib
import platform
import plistlib
import re
import shutil
import subprocess

root = pathlib.Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument("--arch", choices=["arm64", "x86_64"], default=platform.machine())
parser.add_argument("--version", default="1.0.3")
parser.add_argument("--skip-dmg", action="store_true")
args = parser.parse_args()
if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-.][A-Za-z0-9.]+)?", args.version):
    parser.error("version must be a semantic version")

def run(*command):
    subprocess.run(command, check=True)

run("swift", "build", "--package-path", str(root), "-c", "release", "--arch", args.arch)
binary_dir = pathlib.Path(subprocess.check_output(["swift", "build", "--package-path", str(root), "-c", "release", "--arch", args.arch, "--show-bin-path"], text=True).strip())
out = root.parent / "artifacts" / "macos" / args.arch
out.mkdir(parents=True, exist_ok=True)
app = out / "bwssh.app"
if app.exists():
    shutil.rmtree(app)
macos = app / "Contents/MacOS"
resources = app / "Contents/Resources"
macos.mkdir(parents=True)
resources.mkdir()
shutil.copy2(binary_dir / "bwssh", macos / "bwssh")
(macos / "bwssh").chmod(0o755)
info = plistlib.loads((root / "Resources/Info.plist").read_bytes())
info["CFBundleShortVersionString"] = args.version
info["CFBundleVersion"] = args.version.split("-")[0]
(app / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
shutil.copy2(root.parent / "LICENSE", resources / "LICENSE")
shutil.copy2(root / "THIRD_PARTY_NOTICES.md", resources / "THIRD_PARTY_NOTICES.md")
shutil.copy2(root / "Sources/CBwCrypto/argon2/LICENSE", resources / "ARGON2-LICENSE")
for filename in ["bcrypt_pbkdf.c", "blowfish.c", "blf.h"]:
    shutil.copy2(root / "Sources/CBwCrypto/openssh" / filename, resources / filename)
iconset = out / "AppIcon.iconset"
iconset.mkdir(exist_ok=True)
for size in [16, 32, 128, 256, 512]:
    for scale in [1, 2]:
        name = f"icon_{size}x{size}" + ("@2x" if scale == 2 else "") + ".png"
        run("sips", "-z", str(size * scale), str(size * scale), str(root.parent / "src/BwSshAgent.App/Assets/app.png"), "--out", str(iconset / name))
run("iconutil", "-c", "icns", str(iconset), "-o", str(resources / "AppIcon.icns"))
shutil.rmtree(iconset)
run("codesign", "--force", "--sign", "-", "--identifier", "com.bwssh.macos", str(app))
run("codesign", "--verify", "--deep", "--strict", str(app))
run("lipo", str(macos / "bwssh"), "-verify_arch", args.arch)
run(str(macos / "bwssh"), "--version") if platform.machine() == args.arch else None
basename = f"bwssh-{args.version}-macos-{args.arch}"
archive = out / (basename + ".zip")
if archive.exists():
    archive.unlink()
run("ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", str(app), str(archive))
outputs = [archive]
if not args.skip_dmg:
    staging = out / "dmg-staging"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir()
    shutil.copytree(app, staging / "bwssh.app")
    (staging / "Applications").symlink_to("/Applications")
    image = out / (basename + ".dmg")
    if image.exists():
        image.unlink()
    run("hdiutil", "create", "-volname", "bwssh", "-srcfolder", str(staging), "-ov", "-format", "UDZO", str(image))
    shutil.rmtree(staging)
    outputs.append(image)
(out / "SHA256SUMS").write_text("".join(f"{hashlib.sha256(file.read_bytes()).hexdigest()}  {file.name}\n" for file in outputs))
print("\nArtifacts: " + str(out))
