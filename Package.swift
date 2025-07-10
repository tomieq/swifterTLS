// swift-tools-version: 5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwifterTLS",
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SwifterTLS",
            targets: ["SwifterTLS"]),
        .executable(name: "Demo",
                    targets: ["Demo"])
    ],
    dependencies: [
        .package(url: "https://github.com/tomieq/swifter.git", branch: "tls"),
        .package(url: "https://github.com/tomieq/SwiftExtensions", from: "1.0.0")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SwifterTLS",
            dependencies: [
                .product(name: "Swifter", package: "Swifter"),
                .product(name: "SwiftExtensions", package: "SwiftExtensions")
            ]),
        .testTarget(
            name: "SwifterTLSTests",
            dependencies: ["SwifterTLS"]
        ),
        .executableTarget(name: "Demo",
                         dependencies: ["SwifterTLS"])
    ]
)
