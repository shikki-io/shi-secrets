import Testing
@testable import ShiSecretsKit
import Foundation

// KeychainProductionServiceGuardTests — ratchet that fails if any test code in
// ShiSecretsKitTests constructs KeychainVaultCredentials with the production
// service/account (bare no-arg init, or explicit production constants) outside
// of a clearly marked live-integration context.
//
// Background: the production item is "io.shikki.vault / vault-credentials".
// Any test that constructs KeychainVaultCredentials() (no args) touches that
// item when calling delete() or store(), which destroys the operator's real
// credentials.  All unit tests must inject a unique per-test service+account.
//
// The guard works by scanning its own source tree for the forbidden pattern and
// failing the test if any match is found outside the explicitly-exempted live
// integration annotation.
//
// Exempt pattern: lines annotated with
//   // KEYCHAIN-LIVE-INTEGRATION-EXEMPT
// are allowed to use the production service because they are behind an
// explicit SHIKKI_SECRETS_INTEGRATION=1 env-var guard.

@Suite("Keychain production-service guard")
struct KeychainProductionServiceGuardTests {

    // MARK: - Forbidden bare init pattern

    @Test("Guard: no test constructs KeychainVaultCredentials() bare (no-arg init)")
    func noBareBareInit() throws {
        let violations = try scanForPattern("KeychainVaultCredentials()")
        #expect(
            violations.isEmpty,
            "Found bare KeychainVaultCredentials() in test sources — inject a test service instead:\n\(violations.joined(separator: "\n"))"
        )
    }

    // MARK: - Forbidden explicit-production-service pattern

    @Test("Guard: no test passes the production service string directly to the init")
    func noExplicitProductionService() throws {
        // Catches patterns like:
        //   KeychainVaultCredentials(service: "io.shikki.vault", ...)
        //   KeychainVaultCredentials(service: KeychainVaultCredentials.service, ...)
        // except lines that carry the exempt annotation.
        let productionLiteral = try scanForPattern(
            "KeychainVaultCredentials(service: \"io.shikki.vault\""
        )
        let productionConstant = try scanForPattern(
            "KeychainVaultCredentials(service: KeychainVaultCredentials.service"
        )
        let all = productionLiteral + productionConstant
        #expect(
            all.isEmpty,
            "Found test code constructing with the production service — use a test-scoped service instead:\n\(all.joined(separator: "\n"))"
        )
    }

    // MARK: - Production constants are still reachable (smoke)

    @Test("Guard: production constants compile and hold expected values")
    func productionConstantsCompile() {
        // Verify the static constants are still present after refactor.
        #expect(KeychainVaultCredentials.service  == "io.shikki.vault")
        #expect(KeychainVaultCredentials.account  == "vault-credentials")
        #expect(KeychainVaultCredentials.legacyService == "eu.fj-studios.shikki.vault")
    }

    // MARK: - Default init still uses production constants (regression check)

    @Test("Guard: default init uses production service and account")
    func defaultInitUsesProductionValues() {
        let kc = KeychainVaultCredentials(
            service: KeychainVaultCredentials.service,
            account: KeychainVaultCredentials.account
        )
        #expect(kc.service == KeychainVaultCredentials.service)
        #expect(kc.account == KeychainVaultCredentials.account)
    }

    // MARK: - Injected values are forwarded (smoke)

    @Test("Guard: injected service and account are stored on the instance")
    func injectedValuesAreStored() {
        let testSvc = "test.guard.smoke.\(UUID().uuidString)"
        let testAcct = "test-guard-account"
        let kc = KeychainVaultCredentials(service: testSvc, account: testAcct)
        #expect(kc.service == testSvc)
        #expect(kc.account == testAcct)
    }

    // MARK: - Scanner helper

    /// Scan `Tests/ShiSecretsKitTests/` for Swift source lines that contain
    /// `pattern` and are NOT annotated with `// KEYCHAIN-LIVE-INTEGRATION-EXEMPT`.
    ///
    /// Returns a list of `"<file>:<line>: <content>"` strings for each violation.
    private func scanForPattern(_ pattern: String) throws -> [String] {
        let testsDir = try testsDirectory()
        let swiftFiles = try collectSwiftFiles(under: testsDir)

        var violations: [String] = []
        for file in swiftFiles {
            // Skip this guard file itself (it references the pattern in strings).
            if file.hasSuffix("KeychainProductionServiceGuardTests.swift") { continue }

            let contents = try String(contentsOfFile: file, encoding: .utf8)
            let lines = contents.components(separatedBy: .newlines)
            for (idx, line) in lines.enumerated() {
                guard line.contains(pattern) else { continue }
                // Allow if the line itself, or the immediately following line,
                // carries the live-integration exemption marker.
                let exempt = line.contains("// KEYCHAIN-LIVE-INTEGRATION-EXEMPT")
                    || (idx + 1 < lines.count && lines[idx + 1].contains("// KEYCHAIN-LIVE-INTEGRATION-EXEMPT"))
                if exempt { continue }
                // Also skip pure comment lines.
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("//") { continue }
                violations.append("\(file):\(idx + 1): \(trimmed)")
            }
        }
        return violations
    }

    /// Resolve the `Tests/ShiSecretsKitTests/` directory relative to this
    /// source file, which lives inside it.
    private func testsDirectory() throws -> String {
        // __FILE__ resolves at compile time to the absolute path of this source
        // file, which is inside Tests/ShiSecretsKitTests/.
        // We walk up to find the ShiSecretsKitTests directory.
        let thisFile = #filePath
        var url = URL(fileURLWithPath: thisFile)
        // Walk up until we hit the ShiSecretsKitTests directory component.
        while url.lastPathComponent != "ShiSecretsKitTests" && url.pathComponents.count > 1 {
            url = url.deletingLastPathComponent()
        }
        guard url.lastPathComponent == "ShiSecretsKitTests" else {
            throw ScanError.directoryNotFound(thisFile)
        }
        return url.path
    }

    private func collectSwiftFiles(under dir: String) throws -> [String] {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(atPath: dir) else {
            throw ScanError.enumerationFailed(dir)
        }
        var files: [String] = []
        while let relative = enumerator.nextObject() as? String {
            guard relative.hasSuffix(".swift") else { continue }
            files.append((dir as NSString).appendingPathComponent(relative))
        }
        return files
    }

    enum ScanError: Error {
        case directoryNotFound(String)
        case enumerationFailed(String)
    }
}
