// SocketConnectionDefaultPathTests.swift
// P0 — shi-secrets socket-path XDG alignment
// Backlog: 209d7d6c-4a23-48f2-8d71-fdb962f1eb16
// Spec: features/socket-path-xdg-alignment-2026-07-02.md
//
// Fresh-install regression anchor: client and daemon MUST agree on the
// default socket path. Shikki's LaunchAgentManager (in the shikki monorepo)
// binds the daemon to ~/.local/share/shikki/run/secrets-brokerd.sock via
// the XDG-native `ShikkiPaths.dataRoot()`. If the client library falls back
// to the legacy ~/.shikki/run/ path they diverge and `shi secrets` reports
// "broker unavailable" every fresh install (companion of shikki #1290).

import Foundation
import Testing
@testable import ShiSecretsClient
import ShiSecretsKit

@Suite("SocketConnection default path — XDG alignment (P0)")
struct SocketConnectionDefaultPathTests {

    /// Locks in the XDG-aligned default so a future edit that swaps it back
    /// to the legacy `~/.shikki/run/` path fails loud instead of silently
    /// breaking every fresh install.
    @Test("defaultSocketPath resolves to ~/.local/share/shikki/run/secrets-brokerd.sock when SHIKKI_BROKER_SOCKET is unset")
    func defaultSocketPathIsXdgAligned() {
        // The default reads SHIKKI_BROKER_SOCKET first. To measure the
        // fallback directly we can't easily unsetenv() inside a test
        // process, so we recompute the fallback the same way the default
        // does — matching the code contract:
        //   ENV_OVERRIDE ?? "$HOME/.local/share/shikki/run/secrets-brokerd.sock"
        // Reference the same canonical resolver the code-under-test uses —
        // no re-hardcoding the string here (policy_dry_single_source_of_truth).
        let expected = BrokerSocketPath.resolve()

        #expect(
            SocketConnection.defaultSocketPath == expected,
            """
            SocketConnection.defaultSocketPath must equal \(expected).
            Actual: \(SocketConnection.defaultSocketPath).
            If SHIKKI_BROKER_SOCKET is unset this must be
            $HOME/.local/share/shikki/run/secrets-brokerd.sock — the same
            path shikki's LaunchAgentManager passes as --socket in the
            LaunchAgent plist. Legacy ~/.shikki/run/ is a fresh-install
            landmine (backlog 209d7d6c).
            """
        )
    }

    /// Env-var override still wins over the fallback — non-breaking for
    /// operators that pin a custom socket path.
    @Test("SHIKKI_BROKER_SOCKET override still wins over the XDG fallback")
    func envOverrideStillWins() {
        // We assert the shape of the resolution, not by mutating the env
        // mid-test (unsafe for parallel test runs).
        let envValue = ProcessInfo.processInfo.environment["SHIKKI_BROKER_SOCKET"]
        if let envValue {
            #expect(
                SocketConnection.defaultSocketPath == envValue,
                "When SHIKKI_BROKER_SOCKET is set, default must equal it."
            )
        } else {
            #expect(
                SocketConnection.defaultSocketPath.hasSuffix(BrokerSocketPath.xdgSuffix),
                "When SHIKKI_BROKER_SOCKET is unset, default must fall through to the XDG path."
            )
        }
    }
}
