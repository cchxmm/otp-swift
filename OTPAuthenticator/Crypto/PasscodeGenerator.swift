import Foundation
import CommonCrypto

/// 核心 HOTP/TOTP 生成器，与安卓版 PasscodeGenerator.java 完全对应。
///
/// 支持算法：
/// - SHA1/SHA256/SHA512/SHA224/SHA384/MD5：RFC 4226 标准动态截取
/// - SM3：HMAC-SM3，依据 GMT 0021-2023 规范截位
/// - CBCSM4：TrCBC-SM4，依据 GMT 0021-2023 规范
enum PasscodeGenerator {

    static let defaultDigits = 6
    static let defaultTimeStepSeconds = 30

    private static let pow10: [UInt64] = [
        1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000,
    ]

    /// 64 位计数器 → 8 字节大端序
    static func longToBytes(_ value: Int64) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 8)
        var v = value
        for i in (0..<8).reversed() {
            bytes[i] = UInt8(v & 0xFF)
            v >>= 8
        }
        return bytes
    }

    /// 生成 OTP 口令
    static func generate(counter: Int64, secret: [UInt8], algorithm: HashAlgorithm, digits: Int) throws -> String {
        guard digits >= 1 && digits <= 9 else {
            throw NSError(domain: "PasscodeGenerator", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "digits must be 1..9, got \(digits)"])
        }
        guard !secret.isEmpty else {
            throw NSError(domain: "PasscodeGenerator", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "secret is empty"])
        }

        // ======= CBC-SM4 特殊路径 =======
        if algorithm.isCbcSm4 {
            let challenge = longToBytes(counter)
            let inputBytes = padTo128bit(challenge)
            let mac = SM4.cbcMac(input: inputBytes, key: secret)
            let od = cbcSm4Truncation(mac)
            let unsignedOd = UInt64(bitPattern: Int64(od)) & 0xFFFFFFFF
            let code = unsignedOd % pow10[digits]
            return padWithZeros(Int(code), digits)
        }

        // ======= HMAC 路径 =======
        let challenge = longToBytes(counter)
        // SM3 依据 GMT 0021-2023：输入序列不足 128bit 在末端填 0 至 128bit
        let inputBytes = algorithm.isSm3 ? padTo128bit(challenge) : challenge

        let hash: [UInt8]
        if algorithm.isSm3 {
            hash = SM3.hmac(key: secret, data: inputBytes)
        } else {
            hash = try computeHmac(key: secret, data: inputBytes, algorithm: algorithm)
        }

        // 截位运算
        if algorithm.isSm3 {
            let od = sm3DynamicTruncation(hash)
            let unsignedOd = UInt64(bitPattern: Int64(od)) & 0xFFFFFFFF
            let code = unsignedOd % pow10[digits]
            return padWithZeros(Int(code), digits)
        } else {
            return truncate(hash, digits)
        }
    }

    /// 使用 CommonCrypto 计算 HMAC（SHA1/SHA256/SHA512/SHA224/SHA384/MD5）
    private static func computeHmac(key: [UInt8], data: [UInt8], algorithm: HashAlgorithm) throws -> [UInt8] {
        let (alg, digestLen): (CCHmacAlgorithm, Int)
        switch algorithm {
        case .sha1:   (alg, digestLen) = (CCHmacAlgorithm(kCCHmacAlgSHA1),   Int(CC_SHA1_DIGEST_LENGTH))
        case .sha256: (alg, digestLen) = (CCHmacAlgorithm(kCCHmacAlgSHA256), Int(CC_SHA256_DIGEST_LENGTH))
        case .sha512: (alg, digestLen) = (CCHmacAlgorithm(kCCHmacAlgSHA512), Int(CC_SHA512_DIGEST_LENGTH))
        case .sha224: (alg, digestLen) = (CCHmacAlgorithm(kCCHmacAlgSHA224), Int(CC_SHA224_DIGEST_LENGTH))
        case .sha384: (alg, digestLen) = (CCHmacAlgorithm(kCCHmacAlgSHA384), Int(CC_SHA384_DIGEST_LENGTH))
        case .md5:    (alg, digestLen) = (CCHmacAlgorithm(kCCHmacAlgMD5),    Int(CC_MD5_DIGEST_LENGTH))
        case .sm3, .cbcsm4:
            throw NSError(domain: "PasscodeGenerator", code: 3,
                          userInfo: [NSLocalizedDescriptionKey: "Use SM3/SM4 path for \(algorithm.canonical)"])
        }

        var result = [UInt8](repeating: 0, count: digestLen)
        key.withUnsafeBytes { keyPtr in
            data.withUnsafeBytes { dataPtr in
                CCHmac(alg, keyPtr.baseAddress, key.count,
                       dataPtr.baseAddress, data.count, &result)
            }
        }
        return result
    }

    /// 输入序列填充至 128bit（16 字节）— 依据 GMT 0021-2023
    private static func padTo128bit(_ input: [UInt8]) -> [UInt8] {
        if input.count >= 16 { return input }
        var padded = [UInt8](repeating: 0, count: 16)
        padded.replaceSubrange(0..<input.count, with: input)
        return padded
    }

    /// SM3 截位运算 — 依据 GMT 0021-2023
    /// 将 256bit 输出划分为 8 个 4 字节整数 S1..S8
    /// OD = (S1+...+S8) mod 2^32
    private static func sm3DynamicTruncation(_ hash: [UInt8]) -> Int64 {
        assert(hash.count >= 32, "SM3 HMAC output must be 32 bytes")
        var sum: UInt64 = 0
        let mod: UInt64 = 0x100000000 // 2^32
        for i in 0..<8 {
            let s = (UInt64(hash[i * 4]) << 24)
                  | (UInt64(hash[i * 4 + 1]) << 16)
                  | (UInt64(hash[i * 4 + 2]) << 8)
                  | UInt64(hash[i * 4 + 3])
            sum = (sum + s) % mod
        }
        return Int64(bitPattern: sum)
    }

    /// CBC-SM4 截位运算 — 依据 GMT 0021-2023
    /// 将 128bit MAC 输出划分为 4 个 4 字节整数 S1..S4
    /// OD = (S1+S2+S3+S4) mod 2^32
    private static func cbcSm4Truncation(_ mac: [UInt8]) -> Int64 {
        assert(mac.count == 16, "CBC-SM4 MAC must be 16 bytes")
        var sum: UInt64 = 0
        let mod: UInt64 = 0x100000000
        for i in 0..<4 {
            let s = (UInt64(mac[i * 4]) << 24)
                  | (UInt64(mac[i * 4 + 1]) << 16)
                  | (UInt64(mac[i * 4 + 2]) << 8)
                  | UInt64(mac[i * 4 + 3])
            sum = (sum + s) % mod
        }
        return Int64(bitPattern: sum)
    }

    /// RFC 4226 标准动态截取（SHA1/SHA256/SHA512/SHA224/SHA384/MD5）
    private static func truncate(_ hash: [UInt8], _ digits: Int) -> String {
        assert(hash.count >= 4, "hash too short")
        // MD5 输出 16 字节，使用 0x0C 掩码；其他算法输出 ≥20 字节，使用标准 0x0F
        let offsetMask: Int = hash.count >= 20 ? 0x0F : 0x0C
        let offset = Int(hash[hash.count - 1]) & offsetMask

        let raw = (Int(hash[offset] & 0x7F) << 24)
                | (Int(hash[offset + 1] & 0xFF) << 16)
                | (Int(hash[offset + 2] & 0xFF) << 8)
                | Int(hash[offset + 3] & 0xFF)

        let code = raw % Int(pow10[digits])
        return padWithZeros(code, digits)
    }

    /// 左侧补零至指定位数
    private static func padWithZeros(_ code: Int, _ digits: Int) -> String {
        let s = String(code)
        return String(repeating: "0", count: max(0, digits - s.count)) + s
    }

    /// 便捷方法：计算 TOTP
    static func totp(unixSeconds: Int64, secret: [UInt8], algorithm: HashAlgorithm,
                     digits: Int, timeStepSeconds: Int) throws -> String {
        let step = timeStepSeconds <= 0 ? defaultTimeStepSeconds : timeStepSeconds
        let counter = unixSeconds / Int64(step)
        return try generate(counter: counter, secret: secret, algorithm: algorithm, digits: digits)
    }

    /// 便捷方法：计算 HOTP
    static func hotp(counter: Int64, secret: [UInt8], algorithm: HashAlgorithm, digits: Int) throws -> String {
        try generate(counter: counter, secret: secret, algorithm: algorithm, digits: digits)
    }
}
