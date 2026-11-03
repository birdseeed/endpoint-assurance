//
//  PatchedUpdaterApp.swift
//  PatchedUpdater
//
//  Menu bar agent (PAT-476). The posture agent's MenuBarExtra
//  (AgentMenuBarScene) is the app's only scene.
//
//  PAT-1619: the legacy Deploy window (DeployWindowView + CatalogView), its
//  Settings pane and the Self Service hand-offs it hosted were removed. The
//  app now stays LSUIElement (no Dock icon) at all times except while the
//  OS-update blocking prompt is on screen; BlockingUpdateWindowController
//  toggles NSApp's activation policy for that window itself.
//

import SwiftUI

@main
struct PatchedUpdaterApp: App {
    @StateObject private var store = StatusStore()
    @StateObject private var postureStore = PostureStore()
    /// PAT-1624: supplies the managed-tier `interruption_policy` overrides for
    /// the never-interrupt bounds. The gate itself needs no config and runs at
    /// every tier.
    @StateObject private var configStore = AgentConfigStore()

    init() {
        Brand.registerFonts()
    }

    var body: some Scene {
        // PAT-476 posture agent: the single menu-bar surface (tray icon + glanceable
        // popover). `store` (StatusStore) is threaded through so the scene can still
        // summon the OS-update blocking prompt; see AgentMenuBarScene's onChange.
        AgentMenuBarScene(store: postureStore, statusStore: store, configStore: configStore)
    }
}
