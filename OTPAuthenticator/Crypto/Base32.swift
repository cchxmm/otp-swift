import Foundation

/// Base32 (RFC 4648) 编解码器，与安卓版 Base32.java 完全一致。
enum Base32 {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    private static let padding: Character = "="

    /// 解码 Base32 字符串为字节数组
    static func decode(_ input: String) throws -> [UInt8] {
        // 去除空白、padding，转大写
        var s = input
        s = s.replacingOccurrences(of: "\\s+", with: "", options: .regularExpression)
        s = s.replacingOccurrences(of: String(padding), with: "")
        s = s.uppercased()
        if s.isEmpty { return [] }

        // 校验字符
        for ch in s {
            if !alphabet.contains(ch) {
                throw NSError(
                    domain: "Base32",
                    code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "无效的 Base32 字符: '\(ch)'"]
                )
            }
        }

        let byteLength = s.count * 5 / 8
        var result = [UInt8](repeating: 0, count: byteLength)
        var buffer: UInt64 = 0
        var bits = 0
        var outIdx = 0

        for ch in s {
            guard let value = alphabet.firstIndex(of: ch) else { continue }
            buffer = (buffer << 5) | UInt64(value)
            bits += 5
            if bits >= 8 {
                bits -= 8
                result[outIdx] = UInt8((buffer >> UInt64(bits)) & 0xFF)
                outIdx += 1
                if outIdx >= byteLength { break }
            }
        }
        return result
    }

    /// 编码字节数组为 Base32 字符串
    static func encode(_ data: [UInt8]) -> String {
        if data.isEmpty { return "" }
        var sb = ""
        var buffer: Int = 0
        var bitsLeft = 0
        for b in data {
            buffer = (buffer << 8) | Int(b)
            bitsLeft += 8
            while bitsLeft >= 5 {
                let index = (buffer >> (bitsLeft - 5)) & 0x1F
                sb.append(alphabet[index])
                bitsLeft -= 5
            }
        }
        if bitsLeft > 0 {
            let index = (buffer << (5 - bitsLeft)) & 0x1F
            sb.append(alphabet[index])
        }
        return sb
    }
}
