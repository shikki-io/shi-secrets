// DevModeTests — W1.1 RED suite per spec
// shi-secrets-setup-install-fix-and-dev-mode-2026-06-19.
//
// T4 — --dev-mode flag parsed, in-memory vault seeded with N≥4 creds
// T5 — get/set/list/delete work in dev-mode WITHOUT auth handshake
// T6 — --dev-mode refuses production socket path (~/.shikki/run/)
// T7 — --dev-mode refuses launchd launch (XPC_SERVICE_NAME present)
// T8 — --dev-mode refuses SHI_SECRETS_PRODUCTION=1
// T9 — every seeded value MUST be prefixed `dev-`

import XCTest
@testable import ShiSecretsBrokerd

final class DevModeTests: XCTestCase {

    // MARK: - T4: arg parsing + default seed

    func test_T4_devModeArgs_parses_dev_mode_flag() {
        let parsed = DevModeArgs.parse(["--dev-mode"])
        XCTAssertTrue(parsed.enabled)
        XCTAssertNil(parsed.socketPath)
    }

    func test_T4_devModeArgs_parses_socket_pair() {
        let parsed = DevModeArgs.parse(["--dev-mode", "--socket", "/tmp/x.sock"])
        XCTAssertTrue(parsed.enabled)
        XCTAssertEqual(parsed.socketPath, "/tmp/x.sock")
    }

    func test_T4_devModeArgs_parses_socket_equals() {
        let parsed = DevModeArgs.parse(["--dev-mode", "--socket=/tmp/y.sock"])
        XCTAssertEqual(parsed.socketPath, "/tmp/y.sock")
    }

    func test_T4_defaultSeed_has_at_least_4_creds() {
        XCTAssertGreaterThanOrEqual(DevModeConfig.defaultSeed.count, 4)
    }

    func test_T4_defaultSeed_includes_kuma_admin_pair() {
        let names = DevModeConfig.defaultSeed.map(\.name)
        XCTAssertTrue(names.contains("kuma/admin-username"))
        XCTAssertTrue(names.contains("kuma/admin-password"))
    }

    // MARK: - T5: in-memory CRUD without auth

    func test_T5_devModeBootstrap_seeds_and_returns_active_in_memory_client() async throws {
        let cfg = DevModeConfig(
            socketPath: "/tmp/shi-dev-test-T5.sock",
            seedCredentials: [("kuma/admin-username", "dev-admin"),
                              ("kuma/admin-password", "dev-pw-xxx")]
        )
        let boot = DevModeBootstrap(config: cfg)
        let (bw, signingKey) = try await boot.unseal()

        let listed = try await bw.list()
        XCTAssertEqual(Set(listed), Set(["kuma/admin-username", "kuma/admin-password"]))

        let user = try await bw.get(name: "kuma/admin-username")
        XCTAssertEqual(user["value"], "dev-admin")

        // signing key is a real Ed25519 — round-trip via signature
        let payload = Data("ping".utf8)
        let sig = try signingKey.privateKey.signature(for: payload)
        XCTAssertTrue(signingKey.privateKey.publicKey.isValidSignature(sig, for: payload))
    }

    func test_T5_devMode_set_then_get_round_trips() async throws {
        let cfg = DevModeConfig(socketPath: "/tmp/shi-dev-T5b.sock", seedCredentials: [])
        let (bw, _) = try await DevModeBootstrap(config: cfg).unseal()
        try await bw.set(name: "kuma/new-key", value: "dev-fresh-value")
        let got = try await bw.get(name: "kuma/new-key")
        XCTAssertEqual(got["value"], "dev-fresh-value")
    }

    // MARK: - T6: production socket path refusal

    func test_T6_refuses_production_socket_path_under_home_shikki_run() {
        // Use a non-tilde absolute path that ends with /.shikki/run/<sock>
        let prodPath = "/Users/anyone/.shikki/run/secrets-brokerd.sock"
        XCTAssertThrowsError(try DevModeSafety.assertSocketSafe(prodPath)) { err in
            guard case DevModeError.productionSocketPathRefused = err else {
                return XCTFail("expected productionSocketPathRefused, got \(err)")
            }
        }
    }

    func test_T6_allows_tmp_socket_path() throws {
        try DevModeSafety.assertSocketSafe("/tmp/shi-dev-test.sock")
    }

    // MARK: - T7: launchd refusal

    func test_T7_refuses_when_xpc_service_name_is_reverse_dns() {
        // W3 mandate 2026-06-24: canonical label is io.shikki.secrets-brokerd.
        // The old eu.fj-studios.shikki.secrets-brokerd label also triggers refusal (contains dot).
        // Both are valid reverse-DNS patterns that launchd uses for XPC_SERVICE_NAME.
        XCTAssertThrowsError(try DevModeSafety.assertEnvSafe(env: ["XPC_SERVICE_NAME": "io.shikki.secrets-brokerd"])) { err in
            guard case DevModeError.launchdLaunchRefused = err else {
                return XCTFail("expected launchdLaunchRefused, got \(err)")
            }
        }
    }

    func test_T7_allows_xctest_sentinel() throws {
        // XCTest sets XPC_SERVICE_NAME=0 — not a real launchd service.
        try DevModeSafety.assertEnvSafe(env: ["XPC_SERVICE_NAME": "0"])
    }

    func test_T7_allows_empty_env() throws {
        try DevModeSafety.assertEnvSafe(env: [:])
    }

    // MARK: - T8: production flag refusal

    func test_T8_refuses_when_production_flag_set() {
        XCTAssertThrowsError(try DevModeSafety.assertEnvSafe(env: ["SHI_SECRETS_PRODUCTION": "1"])) { err in
            guard case DevModeError.productionFlagSet = err else {
                return XCTFail("expected productionFlagSet, got \(err)")
            }
        }
    }

    // MARK: - T9: seed leak-grep guard

    func test_T9_refuses_seed_value_not_dev_prefixed() {
        let bad = [("kuma/admin-password", "real-password-leak")]
        XCTAssertThrowsError(try DevModeSafety.assertSeedSafe(bad)) { err in
            guard case DevModeError.seedValueNotDevPrefixed(let n) = err else {
                return XCTFail("expected seedValueNotDevPrefixed, got \(err)")
            }
            XCTAssertEqual(n, "kuma/admin-password")
        }
    }

    func test_T9_default_seed_is_safe() throws {
        try DevModeSafety.assertSeedSafe(DevModeConfig.defaultSeed)
    }
}
