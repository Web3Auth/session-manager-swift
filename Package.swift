// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SessionManager",
    platforms: [.iOS(.v14), .macOS(.v11)],
    products: [
        .library(
            name: "SessionManager",
            targets: ["SessionManager"])
    ],
    dependencies: [
        .package(name: "KeychainSwift", url: "https://github.com/evgenyneu/keychain-swift.git", from: "20.0.0"),
        .package(name: "curvelib.swift", url: "https://github.com/tkey/curvelib.swift", branch:"2.0.0"),
    ],
    targets: [
        .target(
            name: "SessionManager",
            dependencies: ["KeychainSwift",
                .product(name: "curveSecp256k1", package: "curvelib.swift"),
            ]
        
        ),
        .testTarget(
            name: "SessionManagerTests",
            dependencies: ["SessionManager"])
    ],
    swiftLanguageVersions: [.v5]
)
