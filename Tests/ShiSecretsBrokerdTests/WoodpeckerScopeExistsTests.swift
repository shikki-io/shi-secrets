import Foundation
import Testing

// WoodpeckerScopeExistsTests — every `--scope X` in .woodpecker.yml must name
// a scope the kagami registry actually defines.
//
// WHY THIS EXISTS. The pipeline invoked `--scope e2e-brokerd-no-vault`, which
// has never been a registered scope. kagami cannot resolve it, so the step
// died before executing anything: state "failure", exit code 0, EMPTY LOG, no
// start or end timestamp. Seven consecutive pipelines failed that way,
// including a plain push of a legal-text commit to main.
//
// It survived because the same file carried a step-level `when:` narrower
// than the top-level one, so pushes to feat/* and fix/* skipped the only step
// and the pipeline reported green having run nothing — the 0|0|0|0 shape.
// A broken gate plus a fake green is indistinguishable from a working CI
// until someone opens a PR to main.
//
// This test is a STRING check against the pipeline file on purpose: it is the
// only thing that can catch a scope name that is valid YAML, valid shell and
// simply does not exist.

@Suite("WoodpeckerScopeExists")
struct WoodpeckerScopeExistsTests {

    /// Walk up from this file to the directory that holds .woodpecker.yml.
    private static func repoRoot() -> URL? {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            if FileManager.default.fileExists(atPath: dir.appendingPathComponent(".woodpecker.yml").path) {
                return dir
            }
            dir = dir.deletingLastPathComponent()
        }
        return nil
    }

    /// Every scope `name = "..."` the kagami registry declares.
    private static func registeredScopes(root: URL) -> Set<String> {
        var names: Set<String> = []
        for file in [".kagami/scopes.override.toml", ".kagami/scopes.toml"] {
            let url = root.appendingPathComponent(file)
            guard let text = try? String(contentsOf: url, encoding: .utf8) else { continue }
            for line in text.components(separatedBy: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                guard trimmed.hasPrefix("name = \"") else { continue }
                let body = trimmed.dropFirst("name = \"".count)
                if let end = body.firstIndex(of: "\"") { names.insert(String(body[body.startIndex..<end])) }
            }
        }
        return names
    }

    /// Every `--scope X` the pipeline invokes.
    private static func invokedScopes(root: URL) throws -> [String] {
        let text = try String(contentsOf: root.appendingPathComponent(".woodpecker.yml"), encoding: .utf8)
        var found: [String] = []
        for rawLine in text.components(separatedBy: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            // A commented line documents the OLD broken name on purpose; it is
            // not an invocation, and counting it would make this test pass on
            // exactly the file it is meant to reject.
            guard !line.hasPrefix("#") else { continue }
            var rest = Substring(line)
            while let r = rest.range(of: "--scope ") {
                let after = rest[r.upperBound...]
                let token = after.prefix { !$0.isWhitespace }
                if !token.isEmpty { found.append(String(token)) }
                rest = after
            }
        }
        return found
    }

    @Test("CI.1: the pipeline file is present and names at least one scope")
    func test_pipelineInvokesAScope() throws {
        // Not a soft skip. This file is part of this repository, so "absent"
        // is a failure, never a reason to return green.
        let root = try #require(Self.repoRoot(), ".woodpecker.yml not found walking up from \(#filePath)")
        let invoked = try Self.invokedScopes(root: root)
        #expect(!invoked.isEmpty, "the pipeline must actually invoke a kagami scope")
    }

    @Test("CI.2: every --scope in .woodpecker.yml is a registered kagami scope")
    func test_everyInvokedScopeIsRegistered() throws {
        let root = try #require(Self.repoRoot())
        let registered = Self.registeredScopes(root: root)
        #expect(registered.count > 1, "registry parse returned \(registered.count) scopes — the parse is broken, not the repo")

        for scope in try Self.invokedScopes(root: root) {
            // ONE interpolated literal, never a `+` concatenation: Comment is
            // ExpressibleByStringInterpolation, so a literal converts and a
            // String produced by `+` does not.
            let known = registered.sorted().joined(separator: ", ")
            #expect(registered.contains(scope),
                    "CI runs `--scope \(scope)` but no kagami scope is named that — kagami cannot resolve it and the step fails with an empty log. Registered: \(known)")
        }
    }

    @Test("CI.3: a step filter never contradicts the pipeline filter")
    func test_noStepLevelFilterNarrowerThanTheTop() throws {
        let root = try #require(Self.repoRoot())
        let text = try String(contentsOf: root.appendingPathComponent(".woodpecker.yml"), encoding: .utf8)
        let executable = text.components(separatedBy: "\n")
            .filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("#") }

        // A second `when:` is what let a feature-branch push skip the only
        // step and still report green. One filter, one owner.
        let whenCount = executable.filter { $0.trimmingCharacters(in: .whitespaces).hasPrefix("when:") }.count
        #expect(whenCount == 1,
                "found \(whenCount) `when:` blocks — a step-level filter narrower than the pipeline filter produces a green pipeline that executed no steps")
    }
}
