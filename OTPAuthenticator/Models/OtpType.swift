import Foundation

/// OTP 类型：TOTP（基于时间）或 HOTP（基于计数器）
enum OtpType: String, Codable, CaseIterable {
    case totp = "totp"
    case hotp = "hotp"

    static func fromString(_ value: String?) -> OtpType {
        guard let v = value?.lowercased() else { return .totp }
        return OtpType(rawValue: v) ?? .totp
    }

    var displayName: String {
        switch self {
        case .totp: return "TOTP"
        case .hotp: return "HOTP"
        }
    }
}
