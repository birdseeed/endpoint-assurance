//
//  PromptWindowShell.swift
//  PatchedUpdater
//
//  PAT-1623 ruling (Andy, 2026-09-12): "Shared: BlockingUpdateWindowController,
//  the window shell, the brand and layout, the deferral row component, and the
//  interruption gate... One visual language for 'Patched needs something from
//  you,' not two near-identical prompts from the same vendor."
//
//  Both BlockingUpdateWindowController (PAT-273, the OS-update deadline
//  prompt) and RemovalPromptWindowController (PAT-1623, this ticket) build
//  their NSWindow through this one function, so the shell cannot drift
//  between the two prompts it hosts. They still own two separate NSWindow
//  instances rather than fighting over one: the "queue, do not stack" rule
//  (StatusStore.attemptRemovalPromptPresentation) guarantees they are never
//  both visible at once, and two instances keep that arbitration a plain
//  boolean check instead of a hand-off dance over shared window state.
//

import AppKit

enum PromptWindowShell {
    static func makeWindow(title: String, width: CGFloat = 480, height: CGFloat = 300) -> NSWindow {
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: width, height: height),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        window.title = title
        window.isReleasedWhenClosed = false
        window.level = .floating
        return window
    }
}
