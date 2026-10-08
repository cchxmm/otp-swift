import Foundation

/// SM4 国密分组密码算法（GB/T 32907-2016 标准），纯 Swift 实现。
/// 分组长度 128 位（16 字节），密钥长度 128 位（16 字节）。
/// 用于 TrCBC-SM4 动态口令算法（GMT 0021-2023）的 CBC-MAC 计算。
enum SM4 {

    // S-box
    private static let sbox: [UInt8] = [
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
    ]

    // 系统参数 FK
    private static let fk: [UInt32] = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]

    // 固定参数 CK
    private static let ck: [UInt32] = [
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269, 0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249, 0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229, 0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209, 0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
    ]

    // MARK: - 基础运算

    private static func rotl(_ x: UInt32, _ n: Int) -> UInt32 {
        let n = n % 32
        return (x << UInt32(n)) | (x >> UInt32(32 - n))
    }

    /// 非线性变换 τ
    private static func tau(_ a: UInt32) -> UInt32 {
        let b0 = Int((a >> 24) & 0xFF)
        let b1 = Int((a >> 16) & 0xFF)
        let b2 = Int((a >> 8) & 0xFF)
        let b3 = Int(a & 0xFF)
        return (UInt32(sbox[b0]) << 24)
             | (UInt32(sbox[b1]) << 16)
             | (UInt32(sbox[b2]) << 8)
             | UInt32(sbox[b3])
    }

    /// 线性变换 L（加密）
    private static func l(_ b: UInt32) -> UInt32 {
        b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)
    }

    /// 线性变换 L'（密钥扩展）
    private static func lp(_ b: UInt32) -> UInt32 {
        b ^ rotl(b, 13) ^ rotl(b, 23)
    }

    /// 合成变换 T（加密轮函数）
    private static func t(_ z: UInt32) -> UInt32 { l(tau(z)) }

    /// 合成变换 T'（密钥扩展轮函数）
    private static func tp(_ z: UInt32) -> UInt32 { lp(tau(z)) }

    /// 密钥扩展：生成 32 个轮密钥
    private static func expandKey(_ key: [UInt8]) -> [UInt32] {
        var k = [UInt32](repeating: 0, count: 36)
        for i in 0..<4 {
            let ki = (UInt32(key[i * 4]) << 24)
                   | (UInt32(key[i * 4 + 1]) << 16)
                   | (UInt32(key[i * 4 + 2]) << 8)
                   | UInt32(key[i * 4 + 3])
            k[i] = ki ^ fk[i]
        }
        var rk = [UInt32](repeating: 0, count: 32)
        for i in 0..<32 {
            k[i + 4] = k[i] ^ tp(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ ck[i])
            rk[i] = k[i + 4]
        }
        return rk
    }

    /// 加密单个 16 字节分组（ECB）
    static func encryptBlock(_ input: [UInt8], key: [UInt8]) -> [UInt8] {
        assert(input.count == 16, "SM4 input must be 16 bytes")
        assert(key.count == 16, "SM4 key must be 16 bytes")

        let rk = expandKey(key)
        var x = [UInt32](repeating: 0, count: 36)
        for i in 0..<4 {
            x[i] = (UInt32(input[i * 4]) << 24)
                 | (UInt32(input[i * 4 + 1]) << 16)
                 | (UInt32(input[i * 4 + 2]) << 8)
                 | UInt32(input[i * 4 + 3])
        }

        for i in 0..<32 {
            x[i + 4] = x[i] ^ t(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i])
        }

        // 反序变换
        var result = [UInt8](repeating: 0, count: 16)
        for i in 0..<4 {
            let val = x[35 - i]
            result[i * 4]     = UInt8((val >> 24) & 0xFF)
            result[i * 4 + 1] = UInt8((val >> 16) & 0xFF)
            result[i * 4 + 2] = UInt8((val >> 8) & 0xFF)
            result[i * 4 + 3] = UInt8(val & 0xFF)
        }
        return result
    }

    // MARK: - TrCBC-SM4 CBC-MAC

    /// TrCBC-SM4 CBC-MAC — 依据 GMT 0021-2023 规范
    /// S_0 = 0, S_i = SM4(S_{i-1} ADD P_i, K)
    /// ADD 为 128 位无符号算术加法（非 XOR）
    static func cbcMac(input: [UInt8], key: [UInt8]) -> [UInt8] {
        if input.isEmpty {
            return [UInt8](repeating: 0, count: 16)
        }

        // 取密钥前 16 字节，不足补 0
        var sm4Key: [UInt8]
        if key.count >= 16 {
            sm4Key = Array(key[0..<16])
        } else {
            sm4Key = key + [UInt8](repeating: 0, count: 16 - key.count)
        }

        var sPrev = [UInt8](repeating: 0, count: 16) // S_0 = 0

        for offset in stride(from: 0, to: input.count, by: 16) {
            var block = [UInt8](repeating: 0, count: 16)
            let end = min(offset + 16, input.count)
            for i in offset..<end {
                block[i - offset] = input[i]
            }
            let combined = add128(block, sPrev)
            sPrev = encryptBlock(combined, key: sm4Key)
        }
        return sPrev
    }

    /// 128 位无符号加法 mod 2^128
    private static func add128(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: 16)
        var carry: Int = 0
        for i in (0..<16).reversed() {
            let sum = Int(a[i]) + Int(b[i]) + carry
            result[i] = UInt8(sum & 0xFF)
            carry = sum >> 8
        }
        return result
    }
}
