//
//  BrandTokens.swift
//  PatchedUpdater
//
//  Pivot / Quiet brand palette and typography for SwiftUI.
//  Colours match kit/tokens.css exactly; fonts are programmatically registered
//  from bundled .ttf/.otf files at app launch.
//

import SwiftUI
import CoreText

enum Brand {

    // MARK: - Palette

    static let snow     = Color(red: 1,        green: 1,        blue: 1)
    static let paper    = Color(red: 0.961,    green: 0.961,    blue: 0.953)  // #f5f5f3
    static let slate    = Color(red: 0.059,    green: 0.067,    blue: 0.082)  // #0f1115
    static let graphite = Color(red: 0.165,    green: 0.176,    blue: 0.200)  // #2a2d33
    static let mute     = Color(red: 0.490,    green: 0.502,    blue: 0.537)  // #7d8089
    static let signal   = Color(red: 0.961,    green: 0.325,    blue: 0.039)  // #f5530a
    static let secure   = Color(red: 0.110,    green: 0.604,    blue: 0.329)  // #1c9a54
    static let critical = Color(red: 0.886,    green: 0.231,    blue: 0.180)  // #e23b2e

    static let rule     = Color.primary.opacity(0.12)
    static let hair     = Color.primary.opacity(0.07)

    // MARK: - Derived tokens (PAT-300)

    static var signalWash: Color { signal.opacity(0.08) }
    static var card: Color { paper }        // grouped-inset card surface
    static var surface: Color { snow }      // scroll-area background

    // MARK: - Typography

    static func display(_ size: CGFloat, weight: Font.Weight = .bold) -> Font {
        .custom("Archivo", size: size).weight(weight)
    }

    static func sans(_ size: CGFloat, weight: Font.Weight = .regular) -> Font {
        .system(size: size, weight: weight, design: .default)
    }

    static func mono(_ size: CGFloat, weight: Font.Weight = .regular) -> Font {
        .system(size: size, weight: weight, design: .monospaced)
    }

    // MARK: - Font registration

    static func registerFonts() {
        // Only Archivo is registered — used exclusively for the ring-mark header
        // lockup. All other UI text uses SF Pro / SF Mono (system fonts). Inter
        // and JetBrains Mono are web-only; native agents use system fonts per
        // the brand directive (CLAUDE.md § Desktop UI).
        guard let url = Bundle.main.url(forResource: "Archivo-variable", withExtension: "ttf") else { return }
        CTFontManagerRegisterFontsForURL(url as CFURL, .process, nil)
    }
}
