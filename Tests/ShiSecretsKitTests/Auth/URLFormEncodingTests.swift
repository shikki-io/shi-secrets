import Foundation
import Testing
@testable import ShiSecretsKit

@Suite("application/x-www-form-urlencoded value encoding")
struct URLFormEncodingTests {

    /// A base64 client_secret holds `+`, `/` and `=`. Left bare, the server reads
    /// `+` as a space and rejects the key with "Incorrect client_secret".
    @Test("Reserved form characters are percent-encoded", arguments: [
        ("a+b", "a%2Bb"),
        ("a&b", "a%26b"),
        ("a=b", "a%3Db"),
        ("a/b", "a%2Fb"),
        ("a b", "a%20b"),
    ])
    func reservedCharacters(raw: String, encoded: String) {
        #expect(raw.urlFormEncoded == encoded)
    }

    @Test("Unreserved characters stay as they are")
    func unreservedCharacters() {
        let raw = "user.e7b6-AZaz09_~"
        #expect(raw.urlFormEncoded == raw)
    }
}
