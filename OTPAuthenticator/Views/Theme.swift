import SwiftUI

/// Material Design 3 颜色方案，与安卓版 colors.xml 完全一致
extension Color {
    // Primary
    static let mdPrimary = Color(red: 0x3B/255, green: 0x5B/255, blue: 0xDB/255)       // #3B5BDB
    static let mdOnPrimary = Color.white
    static let mdPrimaryContainer = Color(red: 0xDD/255, green: 0xE1/255, blue: 0xFF/255) // #DDE1FF
    static let mdOnPrimaryContainer = Color(red: 0x00/255, green: 0x12/255, blue: 0x57/255) // #001257

    // Surface / Background
    static let mdSurface = Color(red: 0xFC/255, green: 0xFB/255, blue: 0xFF/255)       // #FCFBFF
    static let mdBackground = Color(red: 0xFC/255, green: 0xFB/255, blue: 0xFF/255)    // #FCFBFF
    static let mdOnSurface = Color(red: 0x1B/255, green: 0x1B/255, blue: 0x1F/255)    // #1B1B1F
    static let mdSurfaceVariant = Color(red: 0xE2/255, green: 0xE1/255, blue: 0xEC/255) // #E2E1EC

    // Outline
    static let mdOutline = Color(red: 0x77/255, green: 0x76/255, blue: 0x80/255)       // #777680
    static let mdOutlineVariant = Color(red: 0xC6/255, green: 0xC5/255, blue: 0xD0/255) // #C6C5D0

    // Error
    static let mdError = Color(red: 0xBA/255, green: 0x1A/255, blue: 0x1A/255)         // #BA1A1A
}
