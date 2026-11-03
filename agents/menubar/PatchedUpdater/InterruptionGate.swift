//
//  InterruptionGate.swift
//  PatchedUpdater
//
//  PAT-1624: the "never interrupt" gate.
//
//  One gate, `InterruptionGate.canInterruptNow()`, consulted by every
//  user-facing prompt the agent raises. Today that is the OS-update blocking
//  prompt (PAT-273); removal (PAT-1623) is next. Special-casing the camera
//  would leave a gap the first time somebody dials into a call with video off,
//  so the gate reads four signals and any one of them is enough to stay quiet.
//
//  PRIVACY, NOT OPTIONAL. Every signal below is evaluated as a boolean at
//  decision time and thrown away. This file never records, retains or uploads
//  which application held the camera or the microphone, when it held it, or for
//  how long. "Camera in use 14:02 to 15:30" is attendance monitoring and Patched
//  does not collect it. The only thing that leaves this file is a reason code.
//
//  NO TCC, NO PERMISSION PROMPT, NO PRIVACY INDICATOR. The camera signal reads
//  `kCMIODevicePropertyDeviceIsRunningSomewhere` through CoreMediaIO's object
//  property interface. It never constructs an `AVCaptureDevice` or an
//  `AVCaptureSession`, so it never requests camera consent and never lights the
//  green indicator; that was verified empirically before this code was written
//  (clean run, zero TCC.db entry, zero TCC-related unified-log lines). The
//  microphone signal is the CoreAudio equivalent and behaves the same way. The
//  window and display signals use CoreGraphics geometry only, which needs no
//  Screen Recording grant (window *titles* would; this file never asks for one).
//  The agent bundle carries no camera or microphone usage description and no
//  entitlements file, and adding either would defeat the whole point.
//
//  FAIL CLOSED TOWARD SILENCE. A signal that cannot be read is treated as busy,
//  not as clear. A delayed prompt costs a day. A window over a customer demo
//  costs the account.
//

import Foundation
import CoreGraphics
import CoreMediaIO
import CoreAudio

// MARK: - Reason codes

/// Why the agent stayed quiet. This is the *entire* payload of a suppression
/// event: no application name, no bundle id, no device name, no duration.
enum InterruptionReason: String, Equatable, CaseIterable {
    case cameraInUse        = "camera_in_use"
    case microphoneInUse    = "microphone_in_use"
    case presenting         = "presenting"
    case focusOrDoNotDisturb = "focus_or_do_not_disturb"
    /// A signal could not be read, so the gate assumed the worst.
    case signalUnreadable   = "signal_unreadable"
}

/// A single signal's answer. `unreadable` is deliberately distinct from `busy`
/// so the reason code an admin sees says which of the two happened.
enum SignalReading: Equatable {
    case idle
    case busy
    case unreadable
}

// MARK: - Signal source seam

/// The four signals the gate consults. Injectable so the bounds and decision
/// logic can be tested without a real camera, a real call or a real projector.
protocol InterruptionSignalSource {
    func cameraReading() -> SignalReading
    func microphoneReading() -> SignalReading
    func presentingReading() -> SignalReading
    func focusReading() -> SignalReading
}

// MARK: - Decision

enum InterruptionDecision: Equatable {
    case allow
    case suppress(InterruptionReason)

    var isAllowed: Bool { self == .allow }

    var reason: InterruptionReason? {
        if case .suppress(let reason) = self { return reason }
        return nil
    }
}

// MARK: - The gate

struct InterruptionGate {

    let source: InterruptionSignalSource

    init(source: InterruptionSignalSource = SystemInterruptionSignals()) {
        self.source = source
    }

    /// The one question every user-facing prompt asks before it appears.
    ///
    /// Evaluation is two-pass on purpose. The first pass looks for a signal
    /// that is definitely busy, in a fixed order, so an admin looking at a
    /// device that is not progressing gets the most informative reason
    /// available. Only if nothing is definitely busy does the second pass fall
    /// back to `signalUnreadable`, which still suppresses. Both passes end in
    /// silence, so the ordering only ever changes the reason code, never the
    /// decision.
    func canInterruptNow() -> InterruptionDecision {
        let readings: [(InterruptionReason, SignalReading)] = [
            (.cameraInUse,          source.cameraReading()),
            (.microphoneInUse,      source.microphoneReading()),
            (.presenting,           source.presentingReading()),
            (.focusOrDoNotDisturb,  source.focusReading()),
        ]

        for (reason, reading) in readings where reading == .busy {
            return .suppress(reason)
        }
        for (_, reading) in readings where reading == .unreadable {
            return .suppress(.signalUnreadable)
        }
        return .allow
    }
}

// MARK: - Live signal source

/// Reads the real machine. Every read is bounded, synchronous and cheap: the
/// gate is consulted on a 2-hour cadence and on unlock, not in a loop.
struct SystemInterruptionSignals: InterruptionSignalSource {

    /// Overrides the Do Not Disturb database location for tests. Production
    /// always uses the real path under the calling user's home directory.
    let doNotDisturbDatabaseURL: URL

    init(doNotDisturbDatabaseURL: URL? = nil) {
        self.doNotDisturbDatabaseURL = doNotDisturbDatabaseURL
            ?? FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/DoNotDisturb/DB/Assertions.json")
    }

    // MARK: Camera (CoreMediaIO)

    /// True when any camera device reports itself running somewhere on the
    /// machine, whichever application is holding it. We never ask which one.
    func cameraReading() -> SignalReading {
        var listAddress = CMIOObjectPropertyAddress(
            mSelector: CMIOObjectPropertySelector(kCMIOHardwarePropertyDevices),
            mScope: CMIOObjectPropertyScope(kCMIOObjectPropertyScopeGlobal),
            mElement: CMIOObjectPropertyElement(kCMIOObjectPropertyElementWildcard)
        )

        var byteSize: UInt32 = 0
        guard CMIOObjectGetPropertyDataSize(
            CMIOObjectID(kCMIOObjectSystemObject), &listAddress, 0, nil, &byteSize
        ) == OSStatus(kCMIOHardwareNoError) else { return .unreadable }

        let stride = MemoryLayout<CMIOObjectID>.size
        guard stride > 0 else { return .unreadable }
        let count = Int(byteSize) / stride
        // No camera devices at all is a clear answer, not an unreadable one.
        guard count > 0 else { return .idle }

        var devices = [CMIOObjectID](repeating: 0, count: count)
        var used: UInt32 = 0
        let listStatus = devices.withUnsafeMutableBufferPointer { buffer -> OSStatus in
            CMIOObjectGetPropertyData(
                CMIOObjectID(kCMIOObjectSystemObject), &listAddress, 0, nil,
                byteSize, &used, buffer.baseAddress!
            )
        }
        guard listStatus == OSStatus(kCMIOHardwareNoError) else { return .unreadable }

        var runningAddress = CMIOObjectPropertyAddress(
            mSelector: CMIOObjectPropertySelector(kCMIODevicePropertyDeviceIsRunningSomewhere),
            mScope: CMIOObjectPropertyScope(kCMIOObjectPropertyScopeWildcard),
            mElement: CMIOObjectPropertyElement(kCMIOObjectPropertyElementWildcard)
        )

        for device in devices.prefix(Int(used) / stride) {
            var isRunning: UInt32 = 0
            var runningUsed: UInt32 = 0
            let status = CMIOObjectGetPropertyData(
                device, &runningAddress, 0, nil,
                UInt32(MemoryLayout<UInt32>.size), &runningUsed, &isRunning
            )
            // One device we cannot interrogate is enough to stay quiet.
            guard status == OSStatus(kCMIOHardwareNoError) else { return .unreadable }
            if isRunning != 0 { return .busy }
        }
        return .idle
    }

    // MARK: Microphone (CoreAudio)

    /// True when any *input* device reports itself running somewhere.
    ///
    /// The input-scope filter is load bearing. `kAudioDevicePropertyDeviceIsRunningSomewhere`
    /// is equally true of output devices, so without it every played track or
    /// system alert would read as "on a call" and the agent would go silent for
    /// good on a machine that plays music all day. Only devices with at least
    /// one input channel are considered.
    func microphoneReading() -> SignalReading {
        var listAddress = AudioObjectPropertyAddress(
            mSelector: kAudioHardwarePropertyDevices,
            mScope: kAudioObjectPropertyScopeGlobal,
            mElement: kAudioObjectPropertyElementMain
        )

        var byteSize: UInt32 = 0
        guard AudioObjectGetPropertyDataSize(
            AudioObjectID(kAudioObjectSystemObject), &listAddress, 0, nil, &byteSize
        ) == noErr else { return .unreadable }

        let stride = MemoryLayout<AudioObjectID>.size
        guard stride > 0 else { return .unreadable }
        let count = Int(byteSize) / stride
        guard count > 0 else { return .idle }

        var devices = [AudioObjectID](repeating: 0, count: count)
        let listStatus = devices.withUnsafeMutableBufferPointer { buffer -> OSStatus in
            var size = byteSize
            return AudioObjectGetPropertyData(
                AudioObjectID(kAudioObjectSystemObject), &listAddress, 0, nil,
                &size, buffer.baseAddress!
            )
        }
        guard listStatus == noErr else { return .unreadable }

        for device in devices {
            switch inputDeviceIsRunning(device) {
            case .busy:       return .busy
            case .unreadable: return .unreadable
            case .idle:       continue
            }
        }
        return .idle
    }

    private func inputDeviceIsRunning(_ device: AudioObjectID) -> SignalReading {
        switch deviceHasInputChannels(device) {
        case .unreadable: return .unreadable
        case .idle:       return .idle       // output-only device: not our business
        case .busy:       break              // has input channels, keep going
        }

        var runningAddress = AudioObjectPropertyAddress(
            mSelector: kAudioDevicePropertyDeviceIsRunningSomewhere,
            mScope: kAudioObjectPropertyScopeGlobal,
            mElement: kAudioObjectPropertyElementMain
        )
        var isRunning: UInt32 = 0
        var size = UInt32(MemoryLayout<UInt32>.size)
        guard AudioObjectGetPropertyData(
            device, &runningAddress, 0, nil, &size, &isRunning
        ) == noErr else { return .unreadable }
        return isRunning != 0 ? .busy : .idle
    }

    /// `.busy` here means "this device has input channels", reusing the tri-state
    /// so an unreadable stream configuration still propagates as unreadable.
    private func deviceHasInputChannels(_ device: AudioObjectID) -> SignalReading {
        var configAddress = AudioObjectPropertyAddress(
            mSelector: kAudioDevicePropertyStreamConfiguration,
            mScope: kAudioObjectPropertyScopeInput,
            mElement: kAudioObjectPropertyElementMain
        )
        var byteSize: UInt32 = 0
        guard AudioObjectGetPropertyDataSize(
            device, &configAddress, 0, nil, &byteSize
        ) == noErr else { return .unreadable }
        guard byteSize >= UInt32(MemoryLayout<AudioBufferList>.size) else { return .idle }

        let raw = UnsafeMutableRawPointer.allocate(
            byteCount: Int(byteSize), alignment: MemoryLayout<AudioBufferList>.alignment
        )
        defer { raw.deallocate() }

        var size = byteSize
        guard AudioObjectGetPropertyData(
            device, &configAddress, 0, nil, &size, raw
        ) == noErr else { return .unreadable }

        let list = UnsafeMutableAudioBufferListPointer(
            raw.assumingMemoryBound(to: AudioBufferList.self)
        )
        for buffer in list where buffer.mNumberChannels > 0 { return .busy }
        return .idle
    }

    // MARK: Presenting

    /// Screen capture, display mirroring, or a frontmost window covering a whole
    /// display. Keynote and PowerPoint presenter mode are the worst possible
    /// moment for a prompt, and a mirrored display usually means a projector.
    func presentingReading() -> SignalReading {
        switch displayReading() {
        case .busy:       return .busy
        case .unreadable: return .unreadable
        case .idle:       break
        }
        return fullScreenWindowReading()
    }

    private func displayReading() -> SignalReading {
        var displayCount: UInt32 = 0
        guard CGGetActiveDisplayList(0, nil, &displayCount) == .success else { return .unreadable }
        guard displayCount > 0 else { return .idle }

        var displays = [CGDirectDisplayID](repeating: 0, count: Int(displayCount))
        guard CGGetActiveDisplayList(displayCount, &displays, &displayCount) == .success else {
            return .unreadable
        }

        for display in displays.prefix(Int(displayCount)) {
            // A mirrored display is a projector or a hardware screen share.
            if CGDisplayMirrorsDisplay(display) != kCGNullDirectDisplay { return .busy }
        }
        return .idle
    }

    /// Bounds and layer only. `kCGWindowName` would need a Screen Recording
    /// grant; geometry does not, and geometry is all this needs. We compare
    /// against `CGDisplayBounds`, which shares CoreGraphics' top-left global
    /// coordinate space with the window list, so no coordinate flipping.
    private func fullScreenWindowReading() -> SignalReading {
        let options: CGWindowListOption = [.optionOnScreenOnly, .excludeDesktopElements]
        guard let raw = CGWindowListCopyWindowInfo(options, kCGNullWindowID) as? [[String: Any]] else {
            return .unreadable
        }

        var displayCount: UInt32 = 0
        guard CGGetActiveDisplayList(0, nil, &displayCount) == .success else { return .unreadable }
        guard displayCount > 0 else { return .idle }
        var displays = [CGDirectDisplayID](repeating: 0, count: Int(displayCount))
        guard CGGetActiveDisplayList(displayCount, &displays, &displayCount) == .success else {
            return .unreadable
        }
        let displayBounds = displays.prefix(Int(displayCount)).map(CGDisplayBounds)

        let ownPid = Int(ProcessInfo.processInfo.processIdentifier)

        // The list is front-to-back, so the first normal-layer window that is
        // not ours is the frontmost thing the user is looking at.
        for window in raw {
            guard let layer = window[kCGWindowLayer as String] as? Int, layer == 0 else { continue }
            if let pid = window[kCGWindowOwnerPID as String] as? Int, pid == ownPid { continue }
            guard let boundsDict = window[kCGWindowBounds as String] as? NSDictionary,
                  let bounds = CGRect(dictionaryRepresentation: boundsDict) else {
                return .unreadable
            }
            for display in displayBounds where covers(display, with: bounds) { return .busy }
            return .idle
        }
        return .idle
    }

    /// One point of slack each way: a full-screen window is reported at exactly
    /// the display bounds, but rounding on scaled displays can shave a fraction.
    private func covers(_ display: CGRect, with window: CGRect) -> Bool {
        let tolerance: CGFloat = 1
        return window.minX <= display.minX + tolerance
            && window.minY <= display.minY + tolerance
            && window.maxX >= display.maxX - tolerance
            && window.maxY >= display.maxY - tolerance
    }

    // MARK: Focus / Do Not Disturb

    /// Best effort, and deliberately so.
    ///
    /// macOS has no public, stable API for reading the current Focus mode. The
    /// one non-private technique that works without adding a TCC-gated
    /// permission is reading the Do Not Disturb assertion store the Focus
    /// subsystem keeps in the user's own home directory: an active Focus writes
    /// an entry into `storeAssertionRecords`, and the key is absent or empty
    /// when nothing is on. It is an undocumented file shape and Apple may
    /// change it, so the rules here are chosen so that being wrong is cheap:
    ///
    ///   * File missing entirely  -> `.idle`. A Mac that has never used Focus
    ///     has no database. Treating that as unreadable would fail closed on
    ///     every such machine and silence the agent permanently, which is a
    ///     worse failure than missing a Focus session.
    ///   * File present but unparseable, or the shape changed -> `.unreadable`,
    ///     which suppresses. If Apple moves the goalposts the agent gets
    ///     quieter, never louder.
    ///   * Assertion records present and non-empty -> `.busy`.
    ///
    /// A false negative here costs nothing extra: camera, microphone and
    /// presenting still carry the gate. A false positive only delays a prompt.
    func focusReading() -> SignalReading {
        let url = doNotDisturbDatabaseURL
        guard FileManager.default.fileExists(atPath: url.path) else { return .idle }

        guard let data = try? Data(contentsOf: url) else { return .unreadable }
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return .unreadable
        }
        guard let entries = root["data"] as? [[String: Any]] else { return .unreadable }

        for entry in entries {
            // Key absent = no assertion right now. Present and non-empty = Focus on.
            guard let records = entry["storeAssertionRecords"] else { continue }
            if let list = records as? [Any], !list.isEmpty { return .busy }
        }
        return .idle
    }
}
