import Foundation
import CryptoKit

/// HMAC 算法枚举，支持 8 种算法
enum HashAlgorithm: String, Codable, CaseIterable {
    case sha1    = "SHA1"
    case sha256  = "SHA256"
    case sha512  = "SHA512"
    case sha224  = "SHA224"
    case sha384  = "SHA384"
    case md5     = "MD5"
    case sm3     = "SM3"
    case cbcsm4  = "SM4"

    /// 标准 otpauth URI 中的算法标识
    var canonical: String { rawValue }

    /// 是否为 SM3 算法（使用 GMT 0021-2023 规范截位）
    var isSm3: Bool { self == .sm3 }

    /// 是否为 CBC-SM4 算法（非 HMAC，基于 CBC-MAC）
    var isCbcSm4: Bool { self == .cbcsm4 }

    /// 是否使用系统 CryptoKit 的标准 HMAC
    var usesCryptoKit: Bool {
        switch self {
        case .sha1, .sha256, .sha512, .sha224, .sha384, .md5:
            return true
        case .sm3, .cbcsm4:
            return false
        }
    }

    /// 从字符串解析算法（兼容多种写法）
    static func fromString(_ value: String?) -> HashAlgorithm {
        guard let raw = value?.trimmingCharacters(in: .whitespaces).uppercased() else {
            return .sha1
        }
        var a = raw
        if a.hasPrefix("HMAC-") { a = String(a.dropFirst(5)) }
        if a.hasPrefix("HMAC")  { a = String(a.dropFirst(4)) }
        switch a {
        case "SHA256", "SHA-256", "256": return .sha256
        case "SHA512", "SHA-512", "512": return .sha512
        case "SHA224", "SHA-224", "224": return .sha224
        case "SHA384", "SHA-384", "384": return .sha384
        case "MD5", "MD-5":              return .md5
        case "SM3", "SM-3":              return .sm3
        case "SM4", "SM-4", "CBC-SM4", "CBCSM4": return .cbcsm4
        case "SHA1", "SHA-1", "1", "":   return .sha1
        default:
            // 尝试匹配 canonical name
            return HashAlgorithm(rawValue: a) ?? .sha1
        }
    }
}
