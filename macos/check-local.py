#!/usr/bin/env python3
"""Run the core XCTest cases on a Command Line Tools-only Mac. No account data is used."""
import pathlib
import re
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parent
subprocess.run(["swift", "build", "--package-path", str(root)], check=True)
build = pathlib.Path(subprocess.check_output(["swift", "build", "--package-path", str(root), "--show-bin-path"], text=True).strip())
tests = root / "Tests/BwCoreTests/CoreTests.swift"
methods = re.findall(r"func (test\w+)\(\)( async)? throws", tests.read_text())
with tempfile.TemporaryDirectory(prefix="bwssh-checks-") as directory:
    main = pathlib.Path(directory) / "Runner.swift"
    calls = []
    for method, is_async in methods:
        calls.append(f'do {{ try {"await " if is_async else ""}suite.{method}(); print("PASS {method}") }} catch {{ XCTFail("{method}: \\(error)") }}')
    main.write_text('import Foundation\n@main struct Runner { static func main() async { let suite = CoreTests()\n' + "\n".join(calls) + '\nfor failure in failures { print("FAIL: " + failure) }; print("\\(failures.count) assertion failures"); exit(failures.isEmpty ? 0 : 1) } }\n')
    objects = list((build / "BwCore.build").glob("*.o")) + list((build / "CBwCrypto.build").rglob("*.o"))
    executable = pathlib.Path(directory) / "checks"
    subprocess.run(["swiftc", "-parse-as-library", "-g", "-I", str(build / "Modules"), "-Xcc", "-fmodule-map-file=" + str(build / "CBwCrypto.build/module.modulemap"), "-Xcc", "-I" + str(root / "Sources/CBwCrypto/include"), str(tests), str(root / "Checks/XCTestShim.swift"), str(main), *map(str, objects), "-o", str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
