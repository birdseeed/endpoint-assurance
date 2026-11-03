//
//  BrandFooter.swift
//  PatchedUpdater
//
//  The pixel-matrix "Patched" wordmark on its dark plate — the brand base of
//  the Deploy window. Image "PatchedWordmarkMatrix" is the white SVG from the
//  brand kit (Assets.xcassets/PatchedWordmarkMatrix.imageset).
//

import SwiftUI

struct BrandFooter: View {
    var body: some View {
        Image("PatchedWordmarkMatrix")
            .resizable()
            .scaledToFit()
            .frame(height: 38)
            .frame(maxWidth: .infinity)
            .frame(height: 66)
            .background(Color(red: 0x16/255, green: 0x17/255, blue: 0x1A/255))
            .accessibilityLabel("Patched")
    }
}
