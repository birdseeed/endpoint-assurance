//
//  UserSessionState.swift
//  PatchedUpdater
//
//  PAT-1624: "is there actually somebody there?"
//
//  The never-interrupt bounds only accrue while a user session is active and
//  unlocked. Locked or logged out is absence, not suppression: a laptop shut in
//  a bag for a day must not arrive at "cannot be prompted" having never been
//  near a camera. This is the seam that tells the two apart.
//

import Foundation
import CoreGraphics

protocol UserSessionStateProviding {
    var isActiveAndUnlocked: Bool { get }
}

struct SystemUserSessionState: UserSessionStateProviding {

    // CGSession's dictionary keys are C string macros, so Swift does not import
    // them as constants. These are the literal values those macros expand to.
    private static let onConsoleKey  = "kCGSSessionOnConsoleKey"
    private static let screenLockKey = "CGSSessionScreenIsLocked"

    var isActiveAndUnlocked: Bool {
        guard let info = CGSessionCopyCurrentDictionary() as? [String: Any] else {
            // The menu-bar agent is an LSUIElement app: it only ever runs inside
            // a GUI login session in the first place, so an unreadable session
            // dictionary means "we could not ask", not "nobody is here".
            // Defaulting to absent would silence the prompt permanently on any
            // machine where this read fails, which is a worse failure than
            // occasionally attempting while switched out. The interruption
            // signals themselves still fail closed; this one does not.
            return true
        }
        // The lock key is absent when the screen is not locked, which is why the
        // default here is false rather than true.
        let onConsole = info[Self.onConsoleKey] as? Bool ?? true
        let locked    = info[Self.screenLockKey] as? Bool ?? false
        return onConsole && !locked
    }
}
