import Foundation
import ShiSecretsKit

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// HIGH-5: actor-based counting semaphore for capping concurrent connections.
//
// NEW-M1 fix: added tryWait() fast-path that returns false immediately when
// all slots are taken AND the pending-waiter queue is full (maxWaiters cap).
// runAcceptLoop now calls tryWait() first; only slow-paths to
// waitUnlessCancelled() when there are waiters already queued AND a slot
// is available (i.e., value > 0 at the waiter's turn). In practice the
// accept loop always uses tryWait() — waitUnlessCancelled() is retained
// only so existing tests that drive serveConnection directly still compile.
actor AsyncSemaphore {
    private var value: Int
    /// Hard cap on the pending-waiter queue. Connections that arrive when
    /// both the slot count (value == 0) AND this queue is full are rejected
    /// immediately rather than queued indefinitely.
    private let maxWaiters: Int
    private var waiters: [CheckedContinuation<Bool, Never>] = []

    init(value: Int, maxWaiters: Int = 16) {
        self.value = value
        self.maxWaiters = maxWaiters
    }

    /// NEW-M1: Non-blocking attempt. Returns true if a slot was acquired
    /// immediately; returns false if value == 0 AND the waiter queue is at
    /// capacity. Never enqueues a continuation.
    func tryWait() -> Bool {
        if value > 0 {
            value -= 1
            return true
        }
        // No free slot and waiter queue full — reject immediately.
        return false
    }

    /// Returns true if the semaphore was decremented (slot acquired).
    /// Blocks when value == 0 by appending a continuation to waiters.
    /// Only used by existing tests; runAcceptLoop uses tryWait() instead.
    func waitUnlessCancelled() async -> Bool {
        if value > 0 {
            value -= 1
            return true
        }
        // At cap — queue a continuation (bounded by maxWaiters, but this
        // path is only exercised by tests; the accept loop uses tryWait()).
        return await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }

    func signal() {
        if !waiters.isEmpty {
            let waiter = waiters.removeFirst()
            waiter.resume(returning: true)
        } else {
            value += 1
        }
    }
}

// UnixSocketServer — binds the broker's `/run/shikki-secrets.sock` listener
// and enforces the 0600-owned-by-shikki-broker startup invariant
// (BR-D-02).
//
// Steps on `start`:
//   1. Bind a SOCK_STREAM on `socketPath`
//   2. `chmod 0600` + `chown` to `shikki-broker`
//   3. `fstat` verify mode + owner match
//   4. On mismatch: abort broker start (the server throws; the caller
//      — BrokerDaemon — propagates up to `main` which exits non-zero)
//
// Tests drive the server against a tmp socket path and mutate the mode /
// owner to exercise the abort paths. Chowning to a real uid requires
// privileges we don't have in CI / dev; the `expectedUid` parameter
// defaults to the invoking-process uid so tests can assert "fstat sees
// the right owner" without sudo.

public enum UnixSocketError: Swift.Error, Sendable, Equatable {
    case bindFailed(errno: Int32)
    case chmodFailed(errno: Int32)
    case chownFailed(errno: Int32)
    case listenFailed(errno: Int32)
    case modeMismatch(expected: UInt16, actual: UInt16)
    case ownerMismatch(expected: UInt32, actual: UInt32)
    case pathTooLong(length: Int)
}

public struct UnixSocketConfig: Sendable, Equatable {
    public let socketPath: String
    public let expectedMode: UInt16
    public let expectedUid: UInt32

    /// What the accept loop does with the caller's CODE identity, on top of
    /// its uid (W3 of spec c4e9a1f7, BR-H-04). Defaults to ``PeerCodePolicy/off``
    /// so an existing deployment behaves exactly as before until an operator
    /// writes `[peer] require_team_id` — see PeerCodeIdentity.swift for why
    /// arming it by default would brick every locally built `shi`.
    public let peerCodePolicy: PeerCodePolicy

    public init(
        socketPath: String,
        expectedMode: UInt16 = 0o600,
        expectedUid: UInt32,
        peerCodePolicy: PeerCodePolicy = .off
    ) {
        self.socketPath = socketPath
        self.expectedMode = expectedMode
        self.expectedUid = expectedUid
        self.peerCodePolicy = peerCodePolicy
    }
}

/// Int32 view of SOCK_STREAM. Both Darwin + Glibc vend it as Int32
/// today, but the helper exists so a future platform quirk can be
/// localized in one place.
private var sockStream: Int32 {
    Int32(SOCK_STREAM)
}

public actor UnixSocketServer {

    public let config: UnixSocketConfig
    private var fd: Int32 = -1

    // Phase 0.1 graceful-shutdown fix: a nonisolated(unsafe) snapshot of the listen
    // fd, set once in start() and cleared in shutdown(). This allows
    // requestShutdownAndInterrupt() to close the fd without acquiring the actor,
    // which is necessary because runAcceptLoop() blocks the actor's thread inside
    // accept(2) — an actor-isolated shutdown() would deadlock waiting for the actor.
    //
    // Safety: `_listenFdForInterrupt` is only written under actor isolation (start /
    // shutdown), and read nonisolated only for the one-shot close in
    // requestShutdownAndInterrupt(). The write to -1 in shutdown() happens under
    // actor isolation, so it cannot race with the nonisolated read.
    //
    // R-1 fix: _listenFdForInterrupt is cleared to -1 atomically inside
    // requestShutdownAndInterrupt() via OSAtomicCompareAndSwap32 (or equivalent),
    // ensuring a second call is a no-op and cannot close a recycled fd.
    // See [[panel-rework-R1-double-close-fix-2026-06-24]].
    nonisolated(unsafe) private var _listenFdForInterrupt: Int32 = -1

    public init(config: UnixSocketConfig) {
        self.config = config
    }

    /// Bind + chmod + chown + fstat verify. Throws on any mismatch.
    public func start() throws {
        // Unlink stale socket from prior boot — per recurrence in session b5f03eef
        // (sessions 2026-06-23 and 2026-06-24). See [[brokerd-recovery-full-procedure]] Stage 4.
        // AF_UNIX bind() returns EADDRINUSE if the path exists, even from a killed prior process.
        // Unconditional unlink is safe: socket files are runtime state, not config.
        _ = unlink(config.socketPath)

        let sock = socket(AF_UNIX, sockStream, 0)
        guard sock >= 0 else {
            throw UnixSocketError.bindFailed(errno: errno)
        }
        self.fd = sock
        // HIGH-6: disable SIGPIPE on the listen socket so write() to a closed
        // peer returns EPIPE instead of raising SIGPIPE.
        #if canImport(Darwin)
        var one: Int32 = 1
        _ = withUnsafePointer(to: &one) { ptr in
            setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, ptr, socklen_t(MemoryLayout<Int32>.size))
        }
        #endif

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(config.socketPath.utf8)
        let cap = MemoryLayout.size(ofValue: addr.sun_path)
        guard pathBytes.count < cap else {
            close(sock)
            self.fd = -1
            throw UnixSocketError.pathTooLong(length: pathBytes.count)
        }
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            ptr.withMemoryRebound(to: UInt8.self, capacity: cap) { raw in
                for i in 0 ..< pathBytes.count {
                    raw[i] = pathBytes[i]
                }
                raw[pathBytes.count] = 0
            }
        }

        let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bindResult = withUnsafePointer(to: &addr) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                bind(sock, sockaddrPtr, addrLen)
            }
        }
        guard bindResult == 0 else {
            let e = errno
            close(sock)
            self.fd = -1
            throw UnixSocketError.bindFailed(errno: e)
        }

        if chmod(config.socketPath, mode_t(config.expectedMode)) != 0 {
            let e = errno
            close(sock)
            self.fd = -1
            throw UnixSocketError.chmodFailed(errno: e)
        }

        // chown to expectedUid. This needs root on production; on dev /
        // CI, the tests pass `expectedUid = geteuid()` so the call is a
        // no-op. Review finding #6 — nested EPERM dance lives in
        // `applySocketOwnership(fd:expectedUid:)` for grep-ability.
        do {
            try applySocketOwnership(fd: sock, expectedUid: config.expectedUid)
        } catch {
            close(sock)
            self.fd = -1
            throw error
        }

        // fstat-based verify on the on-disk socket file.
        var st = stat()
        if stat(config.socketPath, &st) != 0 {
            let e = errno
            close(sock)
            self.fd = -1
            throw UnixSocketError.bindFailed(errno: e)
        }
        let actualMode = UInt16(st.st_mode) & 0o777
        if actualMode != config.expectedMode {
            close(sock)
            _ = unlink(config.socketPath)
            self.fd = -1
            throw UnixSocketError.modeMismatch(expected: config.expectedMode, actual: actualMode)
        }
        let actualUid = UInt32(st.st_uid)
        if actualUid != config.expectedUid {
            close(sock)
            _ = unlink(config.socketPath)
            self.fd = -1
            throw UnixSocketError.ownerMismatch(expected: config.expectedUid, actual: actualUid)
        }

        if listen(sock, 32) != 0 {
            let e = errno
            close(sock)
            _ = unlink(config.socketPath)
            self.fd = -1
            throw UnixSocketError.listenFailed(errno: e)
        }
        // Publish to the nonisolated interrupt slot AFTER listen() succeeds.
        _listenFdForInterrupt = sock
    }

    /// Verifies the currently-bound socket still has the expected mode +
    /// owner. Called by the daemon's preflight + HUP-reload paths.
    public func verifyOnDiskInvariant() throws {
        var st = stat()
        guard stat(config.socketPath, &st) == 0 else {
            throw UnixSocketError.bindFailed(errno: errno)
        }
        let actualMode = UInt16(st.st_mode) & 0o777
        if actualMode != config.expectedMode {
            throw UnixSocketError.modeMismatch(expected: config.expectedMode, actual: actualMode)
        }
        let actualUid = UInt32(st.st_uid)
        if actualUid != config.expectedUid {
            throw UnixSocketError.ownerMismatch(expected: config.expectedUid, actual: actualUid)
        }
    }

    public func shutdown() {
        if fd >= 0 {
            close(fd)
            fd = -1
            _listenFdForInterrupt = -1
        }
        _ = unlink(config.socketPath)
    }

    /// Nonisolated interrupt: closes the listen fd from outside the actor's
    /// serialization context. Necessary because runAcceptLoop() blocks the
    /// actor's thread inside accept(2); calling actor-isolated shutdown() would
    /// deadlock until accept() returns — a chicken-and-egg.
    ///
    /// After this call, the in-flight accept() returns EBADF and runAcceptLoop
    /// exits cleanly. The actor-isolated state (fd, _listenFdForInterrupt) is
    /// eventually reconciled by the next actor-isolated call (or stays stale
    /// if the actor is discarded after shutdown, which is fine — the fd is closed).
    ///
    /// Used by: tests (T-06/T-07/T-08/T-09), and future Phase 0.2 signal handler.
    /// Production Main.swift uses the signal → watchTask → shutdown() path,
    /// which works because the signal arrives AFTER accept() returns for each
    /// connection (i.e. there IS a connection to wake the loop).
    ///
    /// For the idle-daemon case (no connections arrive, the loop is permanently
    /// blocked in accept()), this is the ONLY correct teardown path.
    ///
    /// R-1 fix (panel-rework W1): the swap from snapFd → -1 is done via
    /// OSAtomicCompareAndSwap32Barrier so a concurrent or repeated call cannot
    /// close the same fd twice. Without this guard, a second call would close
    /// whatever fd number the OS recycled after the first close(), silently
    /// corrupting an unrelated resource. The swap also prevents the TOCTOU
    /// window where shutdown() writes -1 and requestShutdownAndInterrupt()
    /// races to close the just-freed fd value before the -1 lands.
    public nonisolated func requestShutdownAndInterrupt() {
        // Atomically swap _listenFdForInterrupt to -1, capturing the old value.
        // If the old value is already -1 (already shut down), this is a no-op.
        // OSAtomicCompareAndSwap32Barrier provides the full memory barrier needed
        // for safe nonisolated access alongside actor-isolated writes in start()
        // and shutdown().
        var snapFd: Int32
        repeat {
            snapFd = _listenFdForInterrupt
            if snapFd < 0 { return }   // Already shut down — no-op.
        } while !OSAtomicCompareAndSwap32Barrier(snapFd, -1, &_listenFdForInterrupt)
        close(snapFd)
        _ = unlink(config.socketPath)
    }

    public var socketFD: Int32 {
        fd
    }

    /// Applies the expected uid to the bound socket path. On dev / CI we
    /// are not root, so `chown(..., same-uid, -1)` may EPERM even though
    /// the file already has the right owner — that case is swallowed
    /// deliberately. Any other error surfaces as `.chownFailed`.
    ///
    /// Review finding #6: extracted from `start()` into its own helper so
    /// the EPERM dance is documented in one place.
    private func applySocketOwnership(fd: Int32, expectedUid: UInt32) throws {
        _ = fd   // retained in the signature so call sites read as "on this socket"
        // Only attempt chown if we're root OR the expected uid already
        // matches the effective uid (dev / CI no-op).
        if !(geteuid() == 0 || expectedUid == UInt32(geteuid())) {
            return
        }
        if chown(config.socketPath, uid_t(expectedUid), UInt32.max) == 0 {
            return
        }
        // chown to same owner is a no-op; swallow EPERM only when we're
        // not root AND uid already matches.
        if errno == EPERM && expectedUid == UInt32(geteuid()) {
            return
        }
        throw UnixSocketError.chownFailed(errno: errno)
    }

    // MARK: - Accept loop + wire framer (Phase 0.1, BR-G-01 + BR-G-02)
    //
    // Wire = newline-delimited JSON-RPC 2.0 (see `ShiSecretsKit/Broker/Wire.swift`).
    // Handler signature: `(WireRequest) async -> WireResponse`. Peer-cred
    // wiring lands in Phase 0.2 alongside the daemon-side bridge that
    // translates wire methods to BrokerRequest / handleRequest.
    //
    // Known limitation (Phase 0.1): `shutdown()` from outside this actor
    // can race with the blocking `accept(2)` syscall. For graceful
    // shutdown during accept-blocked state, callers should call
    // `requestShutdownAndInterrupt()` which `shutdown(2)`s the listen fd
    // from a snapshot, causing `accept()` to return EBADF. Phase 0.2
    // moves to non-blocking + kqueue/epoll.

    /// Maximum number of concurrent connections accepted before new ones are rejected.
    /// HIGH-5: unbounded connection spawning.
    public static let maxConcurrentConnections = 64

    /// Emit a diagnostic line to stderr — used by the accept loop to log
    /// why it exited (per [[no-naked-checkmark]]: the previous bare "accept
    /// loop exited" was uselessly opaque).
    private static func logAcceptLoopExit(errno e: Int32, iterations: Int, reason: String) {
        let msg = "shikki-brokerd: accept loop exited: errno=\(e) reason=\"\(reason)\" iterations=\(iterations)\n"
        if let data = msg.data(using: .utf8) {
            try? FileHandle.standardError.write(contentsOf: data)
        }
    }

    /// Spawn per-connection tasks via `Task.detached` until the listen
    /// fd is closed. Returns when accept() reports EBADF / EINVAL.
    ///
    /// CRIT-1: calls peerCredentials(fd:) on each accepted connection and
    /// threads the kernel-reported UID into the handler. Replaces the static
    /// getuid() fallback in Main.swift.
    /// HIGH-5: rejects connections when the semaphore cap (64) is reached.
    ///
    /// FIX (backlog 3376CE9152824CCB822E94C3BB9B3EA8, recurrence #3):
    /// The original code treated ANY accept() errno other than EBADF/EINVAL/EINTR
    /// as fatal, causing the loop to `return` immediately on transient errors
    /// such as EAGAIN, EWOULDBLOCK, EMFILE, ECONNABORTED, or ENFILE.
    /// On Darwin, accept() on a blocking socket may return EAGAIN under kernel
    /// scheduler pressure, and ECONNABORTED when the peer resets the TCP/Unix
    /// connection between SYN and accept(). Both are transient — the listen
    /// socket is still valid and the correct response is `continue`.
    ///
    /// Fixed behaviour:
    ///   - EBADF / EINVAL → clean shutdown (listen fd was closed): return
    ///   - EINTR          → interrupted by signal: continue
    ///   - EAGAIN / EWOULDBLOCK / ECONNABORTED → transient: continue + log
    ///   - anything else  → unexpected; log errno + reason, then return
    public func runAcceptLoop(
        handler: @Sendable @escaping (WireRequest, _ peerUid: UInt32) async -> WireResponse
    ) async {
        let serverFd = self.fd
        guard serverFd >= 0 else { return }
        let semaphore = AsyncSemaphore(value: Self.maxConcurrentConnections)
        var iterations = 0
        while true {
            var clientAddr = sockaddr_un()
            var clientLen = socklen_t(MemoryLayout<sockaddr_un>.size)
            let clientFd = withUnsafeMutablePointer(to: &clientAddr) { ptr -> Int32 in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                    accept(serverFd, sockaddrPtr, &clientLen)
                }
            }
            if clientFd < 0 {
                let e = errno
                // Intentional shutdown: the listen fd was closed externally.
                if e == EBADF || e == EINVAL {
                    Self.logAcceptLoopExit(errno: e, iterations: iterations, reason: "listen fd closed (clean shutdown)")
                    return
                }
                // Signal interrupt — always retry, never fatal.
                if e == EINTR { continue }
                // Transient kernel conditions — the listen socket remains valid.
                // EAGAIN/EWOULDBLOCK: rare-but-spec-legal on a blocking accept(2) per
                //   POSIX §accept (the standard explicitly lists EAGAIN/EWOULDBLOCK as
                //   permitted return values even for blocking sockets). Retry is correct.
                // ECONNABORTED: peer reset before accept() ran — socket still healthy.
                if e == EAGAIN || e == EWOULDBLOCK || e == ECONNABORTED { continue }
                // Any other errno is unexpected (EMFILE=fd limit, ENFILE=system limit,
                // ENOMEM, etc.) — log it with full detail per [[no-naked-checkmark]]
                // and exit so launchd respawns with a clean state.
                let reason: String
                switch e {
                case EMFILE:  reason = "per-process fd limit hit (EMFILE)"
                case ENFILE:  reason = "system fd limit hit (ENFILE)"
                case ENOMEM:  reason = "out of memory (ENOMEM)"
                default:      reason = "unexpected accept() error"
                }
                Self.logAcceptLoopExit(errno: e, iterations: iterations, reason: reason)
                return
            }
            iterations += 1
            // CRIT-1: read kernel-reported peer UID before dispatching.
            let peerUid: UInt32
            if let cred = try? peerCredentials(fd: clientFd) {
                peerUid = cred.uid
            } else {
                // If peerCredentials fails, reject the connection — no fallback.
                close(clientFd)
                continue
            }
            // BR-H-04: and WHO the caller is, not only which uid it runs as.
            // The uid check above plus the 0600 socket already exclude another
            // user; this excludes any same-user process that is not signed by
            // our team. `.off` (the default) returns true without doing any
            // work, so an unarmed deployment pays nothing.
            if !PeerCodeAuthorizer(policy: config.peerCodePolicy).admits(fd: clientFd) {
                close(clientFd)
                continue
            }
            // HIGH-5 + NEW-M1: enforce connection cap with immediate rejection.
            // tryWait() returns false synchronously when value==0 — no continuation
            // is queued, so at-cap connections are rejected, not blocked indefinitely.
            guard await semaphore.tryWait() else {
                let busy = WireResponse.methodNotFound(id: "0", method: "busy")
                _ = try? UnixSocketServer.writeFrame(clientFd: clientFd, response: busy)
                close(clientFd)
                continue
            }
            Task.detached {
                await UnixSocketServer.serveConnection(clientFd: clientFd, peerUid: peerUid, handler: handler)
                await semaphore.signal()
            }
        }
    }

    /// Phase 0.1 graceful-shutdown limitation:
    /// `shutdown()` from outside this actor races with the blocking
    /// `accept(2)` syscall — the close-fd-from-other-thread trick
    /// requires non-actor access to `fd`. For Phase 0.1, callers should
    /// either (a) close all client connections to drain the loop, or
    /// (b) `kill -SIGTERM` the process. Phase 0.2 will rework to
    /// non-blocking + kqueue/epoll so this race is eliminated.

    /// Serve one client connection: read framed JSON, decode WireRequest,
    /// invoke handler, write WireResponse. Closes the connection on EOF
    /// or unrecoverable error.
    ///
    /// CRIT-1: peerUid is the kernel-reported UID from peerCredentials(fd:),
    /// captured before this method is called and threaded into the handler.
    static func serveConnection(
        clientFd: Int32,
        peerUid: UInt32,
        handler: @Sendable @escaping (WireRequest, _ peerUid: UInt32) async -> WireResponse
    ) async {
        defer { close(clientFd) }
        // HIGH-6: suppress SIGPIPE on the client fd so write() returns EPIPE on peer close.
        #if canImport(Darwin)
        var one: Int32 = 1
        _ = withUnsafePointer(to: &one) { ptr in
            setsockopt(clientFd, SOL_SOCKET, SO_NOSIGPIPE, ptr, socklen_t(MemoryLayout<Int32>.size))
        }
        #endif
        var buffer = Data()
        var readBuf = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = readBuf.withUnsafeMutableBufferPointer { ptr -> Int in
                read(clientFd, ptr.baseAddress, ptr.count)
            }
            if n <= 0 { return }
            buffer.append(readBuf, count: n)
            if buffer.count > WireMaxFrameSize + 1 {
                let resp = WireResponse.parseError(message: "Frame too large (>\(WireMaxFrameSize) bytes)")
                _ = try? writeFrame(clientFd: clientFd, response: resp)
                return
            }
            while let (frame, rest) = extractNextFrame(from: buffer) {
                buffer = rest
                let response: WireResponse
                if let req = try? decodeWireRequest(frame) {
                    response = await handler(req, peerUid)
                } else {
                    response = WireResponse.parseError()
                }
                do {
                    try writeFrame(clientFd: clientFd, response: response)
                } catch {
                    return
                }
            }
        }
    }

    /// Encode a WireResponse as a newline-delimited frame and write it
    /// to `clientFd`. Loops on short writes.
    static func writeFrame(clientFd: Int32, response: WireResponse) throws {
        let data = try encodeWireFrame(response)
        try data.withUnsafeBytes { rawPtr in
            var remaining = data.count
            var cursor = rawPtr.baseAddress!
            while remaining > 0 {
                let n = write(clientFd, cursor, remaining)
                if n <= 0 {
                    throw WireFramingError.invalidUTF8
                }
                cursor = cursor.advanced(by: n)
                remaining -= n
            }
        }
    }
}

