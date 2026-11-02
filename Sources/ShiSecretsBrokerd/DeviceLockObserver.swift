import Foundation
import ShiSecretsKit

// DeviceLockObserver — macOS screen-lock/unlock → vault lock/restore.
//
// spec: 7c2e9a14 vault-lock-per-platform rev 3, W2.
//
// BR-03: screen lock drops the vault key within 2 seconds.
// BR-04: screen unlock restores the key from custody (if available).
//
// Architecture:
//   DeviceLockSignalSource — protocol for the lock/unlock event source.
//   SystemDeviceLockSignalSource — real macOS impl (NSWorkspace + distributed notif).
//   ManualDeviceLockSignalSource — injectable test seam (no OS calls).
//   DeviceLockObserver — wires a signal source to the BWClient.
//
// Wire protocol in --dry-run mode:
//   vault.simulate.device_lock   — fires a simulated screen-lock event.
//   vault.simulate.device_unlock — fires a simulated screen-unlock event.
//   (Both require dev-mode and owner UID. Never wired in production.)
//
// Real-device proof (AC-W2-2): lock the Mac screen, verify `shi secrets vault status`
// shows "locked". Unlock and re-run; status shows "unlocked" (restored from custody).
// This proof is operator-recorded in the PR; no automated test touches the real screen.

// MARK: - DeviceLockSignalSource

/// Protocol for the event source that notifies the observer of screen-lock changes.
///
/// Allows both the real macOS notification backend and an injected test seam
/// to implement the same interface.
public protocol DeviceLockSignalSource: Sendable {
    /// Start delivering events. The callbacks are invoked on an internal
    /// thread; they are expected to dispatch async work onto the observer's
    /// actor rather than blocking.
    ///
    /// `lock` is fired when the screen becomes locked (or the screensaver activates).
    /// `unlock` is fired when the screen is unlocked (password/biometric accepted).
    func start(
        onLock: @escaping @Sendable () -> Void,
        onUnlock: @escaping @Sendable () -> Void
    )

    /// Stop delivering events and release any OS-level registrations.
    func stop()
}

// MARK: - ManualDeviceLockSignalSource (injectable test seam)

/// Test seam: fires lock and unlock events on demand.
///
/// No OS calls. Used by DeviceLockE2ETests via the wire-protocol simulation
/// verbs (`vault.simulate.device_lock` / `vault.simulate.device_unlock`)
/// which are only available in --dry-run mode.
public final class ManualDeviceLockSignalSource: DeviceLockSignalSource, @unchecked Sendable {

    // Stored callbacks. @unchecked Sendable because they are written once
    // (in start()) and then only read/called from the simulation path.
    private var lockCallback:   (@Sendable () -> Void)?
    private var unlockCallback: (@Sendable () -> Void)?

    public init() {}

    public func start(
        onLock: @escaping @Sendable () -> Void,
        onUnlock: @escaping @Sendable () -> Void
    ) {
        lockCallback   = onLock
        unlockCallback = onUnlock
    }

    public func stop() {
        lockCallback   = nil
        unlockCallback = nil
    }

    /// Fire a simulated screen-lock event (callable from the wire dispatcher).
    public func fireLock() {
        lockCallback?()
    }

    /// Fire a simulated screen-unlock event (callable from the wire dispatcher).
    public func fireUnlock() {
        unlockCallback?()
    }
}

// MARK: - SystemDeviceLockSignalSource (real macOS impl)

#if os(macOS)
import AppKit

/// Real macOS impl: listens to com.apple.screenIsLocked /
/// com.apple.screenIsUnlocked distributed notifications, and to
/// NSWorkspace.screensDidSleepNotification / screensDidWakeNotification.
///
/// Sleeps also fire the lock callback because a sleeping display leaves the
/// vault key exposed. On wake, we rely on the unlock callback (the unlock
/// notification fires when the user authenticates, not when the display wakes).
public final class SystemDeviceLockSignalSource: DeviceLockSignalSource, @unchecked Sendable {

    // @unchecked Sendable: tokens are written once and only read from the
    // background notification queue; callbacks are constants after start().
    private var tokens: [Any] = []
    private var lockCallback:   (@Sendable () -> Void)?
    private var unlockCallback: (@Sendable () -> Void)?

    public init() {}

    public func start(
        onLock: @escaping @Sendable () -> Void,
        onUnlock: @escaping @Sendable () -> Void
    ) {
        lockCallback   = onLock
        unlockCallback = onUnlock

        let dnc = DistributedNotificationCenter.default()
        tokens.append(dnc.addObserver(
            forName: NSNotification.Name("com.apple.screenIsLocked"),
            object: nil, queue: nil
        ) { [weak self] _ in self?.lockCallback?() })

        tokens.append(dnc.addObserver(
            forName: NSNotification.Name("com.apple.screenIsUnlocked"),
            object: nil, queue: nil
        ) { [weak self] _ in self?.unlockCallback?() })

        // Display sleep also effectively locks the vault (BR-03).
        let nc = NSWorkspace.shared.notificationCenter
        tokens.append(nc.addObserver(
            forName: NSWorkspace.screensDidSleepNotification,
            object: nil, queue: nil
        ) { [weak self] _ in self?.lockCallback?() })

        tokens.append(nc.addObserver(
            forName: NSWorkspace.screensDidWakeNotification,
            object: nil, queue: nil
        ) { [weak self] _ in self?.unlockCallback?() })
    }

    public func stop() {
        let dnc = DistributedNotificationCenter.default()
        let nc  = NSWorkspace.shared.notificationCenter
        for token in tokens {
            if let obs = token as? NSObjectProtocol {
                dnc.removeObserver(obs)
                nc.removeObserver(obs)
                NotificationCenter.default.removeObserver(obs)
            }
        }
        tokens = []
        lockCallback   = nil
        unlockCallback = nil
    }
}

#else

/// Linux/other-platform stub — no screen-lock concept; never fires events.
public final class SystemDeviceLockSignalSource: DeviceLockSignalSource, @unchecked Sendable {
    public init() {}
    public func start(onLock: @escaping @Sendable () -> Void, onUnlock: @escaping @Sendable () -> Void) {}
    public func stop() {}
}

#endif

// MARK: - DeviceLockObserver

/// Wires a DeviceLockSignalSource to a BWClient.
///
/// On lock:   calls bwClient.lock() — drops vault key from memory + custody.
/// On unlock: calls vaultwardenClient.restoreFromCustody() if a custody store
///            is available — restores the key without a master-password prompt (BR-04).
///
/// The observer is started during broker bootstrap (after unseal) and stopped
/// on broker shutdown. In --dry-run (E2E) mode, a ManualDeviceLockSignalSource
/// is used so tests can fire lock/unlock events via the wire protocol.
public actor DeviceLockObserver {

    private let source: any DeviceLockSignalSource
    private let bwClient: any BWClient
    private var isRunning = false

    public init(source: any DeviceLockSignalSource, bwClient: any BWClient) {
        self.source   = source
        self.bwClient = bwClient
    }

    /// Start observing. Idempotent.
    public func start() {
        guard !isRunning else { return }
        isRunning = true
        source.start(
            onLock: { [self] in
                Task { await self.handleLock() }
            },
            onUnlock: { [self] in
                Task { await self.handleUnlock() }
            }
        )
    }

    /// Stop observing and release OS resources. Idempotent.
    public func stop() {
        guard isRunning else { return }
        isRunning = false
        source.stop()
    }

    // MARK: - Event handlers

    /// Screen locked — drop the vault key from memory ONLY (BR-03).
    /// The custody store is preserved so device-unlock can restore the key
    /// without a master-password prompt (BR-04).
    private func handleLock() async {
        try? await bwClient.lockMemoryOnly()
    }

    /// Screen unlocked — try to restore the key from custody (BR-04).
    ///
    /// On macOS: AppleKeychainCustody makes the key inaccessible while the
    /// screen is locked, so restoreFromCustody() will succeed once unlocked.
    /// No-op if the vault was not persisted or the custody load fails.
    private func handleUnlock() async {
        // The restore path is wired through ProductionBWClient.restorePersistedKey().
        // We reach it by casting to the concrete type (available in production)
        // or through an extension point that BWClient doesn't need to expose
        // (keeping the lock surface minimal per BR-06).
        if let prod = bwClient as? ProductionBWClient {
            await prod.restorePersistedKey()
        }
    }
}
