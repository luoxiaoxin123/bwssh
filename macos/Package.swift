// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "bwssh",
    platforms: [.macOS(.v13)],
    products: [.executable(name: "bwssh", targets: ["bwssh"]), .library(name: "BwCore", targets: ["BwCore"])],
    targets: [
        .target(name: "CBwCrypto", exclude: ["argon2/LICENSE"], publicHeadersPath: "include", cSettings: [
            .headerSearchPath("argon2/include"), .headerSearchPath("argon2/src"), .headerSearchPath("openssh"),
            .define("HAVE_BLF_H"), .define("HAVE_STDLIB_H")
        ]),
        .target(name: "BwCore", dependencies: ["CBwCrypto"]),
        .executableTarget(name: "bwssh", dependencies: ["BwCore"]),
        .testTarget(name: "BwCoreTests", dependencies: ["BwCore"])
    ]
)
