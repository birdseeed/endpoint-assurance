//  RingMark.swift
//  PatchedUpdater
//
//  The Patched ring mark drawn in code — a squircle outline with a signal-orange
//  top-right arc and the letter "P" in Archivo 700. Replaces PixelMark.swift;
//  the pixel-P is now marketing-only (site, decks, merch).
//
//  Source of truth: branding kit v2.0.0 · kit/logo/patched-ring-mark-*.svg
//  Geometry (viewBox 64×64): stroke-width 4.608, inset 2.304, rx 16.64.

import SwiftUI
import AppKit

// MARK: - SwiftUI view

/// Draws the ring mark at any size. Always square.
///
/// - Parameters:
///   - size: Point size of the square canvas.
///   - ink: Ring outline and P glyph colour. Use `.primary` for menu-bar contexts
///     so AppKit can auto-tint it; use `Brand.slate` on light surfaces.
///   - showArc: Paints the signal-orange top-right arc. Pass `false` for
///     single-colour / template contexts.
struct RingMarkView: View {
    var size: CGFloat = 24
    var ink: Color = Brand.slate
    var showArc: Bool = true

    var body: some View {
        Canvas { ctx, canvasSize in
            let s  = canvasSize.width
            let sw = s * 4.608 / 64   // stroke width
            let ins = sw / 2           // inset = half stroke so stroke stays inside
            let rx  = s * 16.64 / 64   // corner radius
            let rect = CGRect(x: ins, y: ins, width: s - ins * 2, height: s - ins * 2)

            // Ring outline
            let ring = Path(roundedRect: rect, cornerRadius: rx)
            ctx.stroke(ring, with: .color(ink), lineWidth: sw)

            // Signal-orange top-right corner arc
            if showArc {
                let arcCX = rect.maxX - rx
                let arcCY = rect.minY + rx
                var arc = Path()
                arc.move(to: CGPoint(x: rect.midX, y: rect.minY))
                arc.addLine(to: CGPoint(x: arcCX, y: rect.minY))
                arc.addRelativeArc(
                    center: CGPoint(x: arcCX, y: arcCY),
                    radius: rx,
                    startAngle: .degrees(-90),
                    delta: .degrees(90)
                )
                ctx.stroke(arc, with: .color(Brand.signal),
                           style: StrokeStyle(lineWidth: sw, lineCap: .round))
            }
        }
        .overlay(
            Text("P")
                .font(.custom("Archivo", size: size * 33.28 / 64).weight(.bold))
                .tracking(size * (-1.33) / 64)
                .foregroundStyle(ink)
        )
        .frame(width: size, height: size)
    }
}

// MARK: - NSImage template for the menu-bar slot

extension Brand {
    /// Template NSImage of the ring mark sized for the macOS menu bar (~18 pt).
    /// Drawn entirely in black so AppKit auto-tints it for light/dark menu bars.
    static func menuBarIcon() -> NSImage {
        let s: CGFloat = 18
        let scale = s / 64
        let sw  = 4.608 * scale
        let ins = sw / 2
        let rx  = 16.64 * scale
        // NSBezierPath: y-up coords — rect.minY is the visual bottom, rect.maxY is top.
        let rect = NSRect(x: ins, y: ins, width: s - ins * 2, height: s - ins * 2)

        let img = NSImage(size: NSSize(width: s, height: s))
        img.lockFocus()
        NSColor.black.setStroke()

        // Ring outline
        let ring = NSBezierPath(roundedRect: rect, xRadius: rx, yRadius: rx)
        ring.lineWidth = sw
        ring.stroke()

        // Top-right corner arc (y-up: "top" = rect.maxY, "right" = rect.maxX).
        // appendArc angles: 0° = right, 90° = up; clockwise=true = CW in y-up.
        let arcCX = rect.maxX - rx
        let arcCY = rect.maxY - rx
        let arc = NSBezierPath()
        arc.move(to: NSPoint(x: rect.midX, y: rect.maxY))
        arc.line(to: NSPoint(x: arcCX, y: rect.maxY))
        arc.appendArc(withCenter: NSPoint(x: arcCX, y: arcCY),
                      radius: rx,
                      startAngle: 90, endAngle: 0, clockwise: true)
        arc.lineWidth = sw
        arc.lineCapStyle = .round
        arc.stroke()

        // "P" glyph — Archivo Bold, centred. Baseline in SVG y-down is 43.8/64.
        // In NSImage y-up: baseline y = s - (43.8 * scale).
        let fontSize = 33.28 * scale
        let pFont = NSFont(name: "Archivo-Bold", size: fontSize)
            ?? NSFont.systemFont(ofSize: fontSize, weight: .bold)
        let attrs: [NSAttributedString.Key: Any] = [
            .font: pFont,
            .foregroundColor: NSColor.black,
            .kern: NSNumber(value: Float(-1.33 * scale)),
        ]
        let pStr = NSAttributedString(string: "P", attributes: attrs)
        let pSize = pStr.size()
        let pOrigin = NSPoint(x: s / 2 - pSize.width / 2,
                              y: s - 43.8 * scale)
        pStr.draw(at: pOrigin)

        img.unlockFocus()
        img.isTemplate = true
        return img
    }
}

// MARK: - Preview

#Preview("Ring mark — sizes") {
    HStack(spacing: 16) {
        ForEach([16, 24, 32, 48] as [CGFloat], id: \.self) { sz in
            RingMarkView(size: sz)
        }
    }
    .padding()
}
