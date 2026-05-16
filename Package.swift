// swift-tools-version: 5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwifterTLS",
    platforms: [
        .macOS(.v11)
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SwifterTLS",
            targets: ["SwifterTLS"]),
        .executable(name: "Demo",
                    targets: ["Demo"])
    ],
    dependencies: [
        .package(url: "https://github.com/tomieq/swifter.git", from: "3.2.0"),
        .package(url: "https://github.com/tomieq/SwiftExtensions", branch: "master"),
        .package(url: "https://github.com/apple/swift-crypto.git", .upToNextMajor(from: "3.12.3"))
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SwifterTLS",
            dependencies: [
                .product(name: "Swifter", package: "Swifter"),
                .product(name: "SwiftExtensions", package: "SwiftExtensions"),
                .product(name: "Crypto", package: "swift-crypto")
            ]),
        .testTarget(
            name: "SwifterTLSTests",
            dependencies: ["SwifterTLS"]
        ),
        .executableTarget(name: "Demo",
                         dependencies: ["SwifterTLS"])
    ]
)
