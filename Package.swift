// swift-tools-version: 6.0
// kagami-scope: exempt
import PackageDescription

// shi-secrets — plugin for the shi-secret:// URI scheme, broker daemon,
// 9 CLI verbs, and secrets resolver pipeline.
//
// Extracted from gh:FJ-Studios/shikki packages/ShikkiSecrets/ (W3-W6).
// Atomic Shikki→Shi rename per [[unified-shi-naming-progressive-migration]].
//
// Spec: features/shi-secrets-uri-scheme-and-plugin-extraction-2026-05-31.md
// BR-SSEC-06: plugin lives at gh:FJ-Studios/shi-secrets, NEVER in monorepo.
// BR-SSEC-07: no typealias shims — atomic cutover.

let package = Package(
    name: "shi-secrets",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "ShiSecretsKit", targets: ["ShiSecretsKit"]),
        .library(name: "ShiSecretsDrivers", targets: ["ShiSecretsDrivers"]),
        .library(name: "ShiSecretsClient", targets: ["ShiSecretsClient"]),
        .library(name: "ShiSecretsCLI", targets: ["ShiSecretsCLI"]),
        .library(name: "ShiSecrets", targets: ["ShiSecrets"]),
        .executable(name: "shi-secrets-brokerd", targets: ["ShiSecretsBrokerd"]),
        .executable(name: "shi-admin-key-ceremony", targets: ["AdminKeyCeremony"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/FJ-Studios/shikki-plugin-api.git", from: "0.1.4"),
    ],
    targets: [
        // MARK: - Core library
        .target(
            name: "ShiSecretsKit",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            exclude: [
                "WIRE_FORMAT.md",
            ],
            resources: [
                .copy("Migrations"),
            ]
        ),
        .target(
            name: "ShiSecretsDrivers",
            dependencies: [
                "ShiSecretsKit",
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .target(
            name: "ShiSecretsClient",
            dependencies: [
                "ShiSecretsKit",
            ]
        ),
        // MARK: - Legacy CLI surface (phases 1-5)
        .target(
            name: "ShiSecretsCLI",
            dependencies: [
                "ShiSecretsKit",
                "ShiSecretsClient",
            ]
        ),
        // MARK: - W3+W4 plugin CLI surface (9 new verbs + PluginCLISurface conformance)
        .target(
            name: "ShiSecrets",
            dependencies: [
                "ShiSecretsKit",
                "ShiSecretsClient",
                .product(name: "ShikkiPluginAPI", package: "shikki-plugin-api"),
            ]
        ),
        // MARK: - Daemon
        .executableTarget(
            name: "ShiSecretsBrokerd",
            dependencies: [
                "ShiSecretsKit",
                "ShiSecretsDrivers",
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            exclude: [
                "ShiSecretsBrokerd.entitlements",
                "Info.plist",
            ],
            linkerSettings: [
                .unsafeFlags([
                    "-Xlinker", "-sectcreate",
                    "-Xlinker", "__TEXT",
                    "-Xlinker", "__info_plist",
                    "-Xlinker", "Sources/ShiSecretsBrokerd/Info.plist",
                ])
            ]
        ),
        // MARK: - Admin ceremony
        .executableTarget(
            name: "AdminKeyCeremony",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            exclude: ["AdminKeyCeremony.entitlements"]
        ),
        // MARK: - Tests
        .testTarget(
            name: "AdminKeyCeremonyTests",
            dependencies: []
        ),
        .testTarget(
            name: "ShiSecretsKitTests",
            dependencies: ["ShiSecretsKit"]
        ),
        .testTarget(
            name: "ShiSecretsDriversTests",
            dependencies: ["ShiSecretsDrivers", "ShiSecretsKit"]
        ),
        .testTarget(
            name: "ShiSecretsBrokerdTests",
            dependencies: [
                "ShiSecretsBrokerd",
                "ShiSecretsKit",
                "ShiSecretsDrivers",
                // Bug 3 fix tests: SecretsBrokerdCommand lives in ShiSecrets.
                "ShiSecrets",
            ]
        ),
        .testTarget(
            name: "ShiSecretsClientTests",
            dependencies: [
                "ShiSecretsClient",
                "ShiSecretsKit",
            ]
        ),
        .testTarget(
            name: "ShiSecretsCLITests",
            dependencies: [
                "ShiSecretsCLI",
                "ShiSecretsClient",
                "ShiSecretsKit",
            ]
        ),
        .testTarget(
            name: "ShiSecretsIntegrationTests",
            dependencies: [
                "ShiSecretsBrokerd",
                "ShiSecretsCLI",
                "ShiSecretsDrivers",
                "ShiSecretsKit",
            ]
        ),
        .testTarget(
            name: "ShiSecretsE2ETests",
            dependencies: [
                "ShiSecretsBrokerd",
                "ShiSecretsCLI",
                "ShiSecretsClient",
                "ShiSecretsDrivers",
                "ShiSecretsKit",
            ]
        ),
    ]
)
