import Foundation

/// SM3 国密哈希算法（GM/T 0004-2012 标准），纯 Swift 实现。
/// 输出 256 位（32 字节）哈希值。用于 HMAC-SM3 动态口令算法。
enum SM3 {
    private static let blockSize = 64 // 512 bit

    // 初始值 IV
    private static let iv: [UInt32] = [
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
    ]

    /// 计算消息的 SM3 哈希值，返回 32 字节
    static func hash(_ message: [UInt8]) -> [UInt8] {
        let padded = pad(message)
        var v = iv

        for offset in stride(from: 0, to: padded.count, by: blockSize) {
            let block = Array(padded[offset..<(offset + blockSize)])
            compress(&v, block)
        }

        var result = [UInt8](repeating: 0, count: 32)
        for i in 0..<8 {
            let val = v[i]
            result[i * 4]     = UInt8((val >> 24) & 0xFF)
            result[i * 4 + 1] = UInt8((val >> 16) & 0xFF)
            result[i * 4 + 2] = UInt8((val >> 8) & 0xFF)
            result[i * 4 + 3] = UInt8(val & 0xFF)
        }
        return result
    }

    /// HMAC-SM3：使用 SM3 作为底层哈希的 HMAC 运算
    static func hmac(key: [UInt8], data: [UInt8]) -> [UInt8] {
        var k = key
        if k.count > blockSize {
            k = hash(k)
        }
        if k.count < blockSize {
            k = k + [UInt8](repeating: 0, count: blockSize - k.count)
        }

        let ipad = k.map { $0 ^ 0x36 }
        let opad = k.map { $0 ^ 0x5C }

        let inner = hash(ipad + data)
        return hash(opad + inner)
    }

    // MARK: - 私有方法

    /// 消息填充
    private static func pad(_ msg: [UInt8]) -> [UInt8] {
        let len = msg.count
        let bitLen = UInt64(len * 8)

        let mod = len % 64
        let padLen = mod < 56 ? (56 - mod) : (120 - mod)
        var padded = [UInt8](repeating: 0, count: len + padLen + 8)
        padded.replaceSubrange(0..<len, with: msg)
        padded[len] = 0x80

        // 最后 8 字节为消息长度（大端序）
        let hi = UInt32(bitLen >> 32)
        let lo = UInt32(bitLen & 0xFFFFFFFF)
        let total = padded.count
        padded[total - 8] = UInt8((hi >> 24) & 0xFF)
        padded[total - 7] = UInt8((hi >> 16) & 0xFF)
        padded[total - 6] = UInt8((hi >> 8) & 0xFF)
        padded[total - 5] = UInt8(hi & 0xFF)
        padded[total - 4] = UInt8((lo >> 24) & 0xFF)
        padded[total - 3] = UInt8((lo >> 16) & 0xFF)
        padded[total - 2] = UInt8((lo >> 8) & 0xFF)
        padded[total - 1] = UInt8(lo & 0xFF)

        return padded
    }

    private static func rotl(_ x: UInt32, _ n: Int) -> UInt32 {
        let n = n % 32
        return (x << UInt32(n)) | (x >> UInt32(32 - n))
    }

    private static func p0(_ x: UInt32) -> UInt32 {
        x ^ rotl(x, 9) ^ rotl(x, 17)
    }

    private static func p1(_ x: UInt32) -> UInt32 {
        x ^ rotl(x, 15) ^ rotl(x, 23)
    }

    private static func ff(_ x: UInt32, _ y: UInt32, _ z: UInt32, _ j: Int) -> UInt32 {
        if j < 16 {
            return x ^ y ^ z
        }
        return (x & y) | (x & z) | (y & z)
    }

    private static func gg(_ x: UInt32, _ y: UInt32, _ z: UInt32, _ j: Int) -> UInt32 {
        if j < 16 {
            return x ^ y ^ z
        }
        return (x & y) | ((~x) & z)
    }

    private static func tj(_ j: Int) -> UInt32 {
        return j < 16 ? 0x79CC4519 : 0x7A879D8A
    }

    private static func compress(_ v: inout [UInt32], _ block: [UInt8]) {
        // 消息扩展：W0..W67
        var w = [UInt32](repeating: 0, count: 68)
        var w1 = [UInt32](repeating: 0, count: 64)

        for i in 0..<16 {
            w[i] = (UInt32(block[i * 4]) << 24)
                 | (UInt32(block[i * 4 + 1]) << 16)
                 | (UInt32(block[i * 4 + 2]) << 8)
                 | UInt32(block[i * 4 + 3])
        }
        for j in 16..<68 {
            w[j] = p1(w[j - 16] ^ w[j - 9] ^ rotl(w[j - 3], 15))
                 ^ rotl(w[j - 13], 7)
                 ^ w[j - 6]
        }
        for j in 0..<64 {
            w1[j] = w[j] ^ w[j + 4]
        }

        // 压缩
        var a = v[0], b = v[1], c = v[2], d = v[3]
        var e = v[4], f = v[5], g = v[6], h = v[7]

        for j in 0..<64 {
            let ss1 = rotl(
                (rotl(a, 12) &+ e &+ rotl(tj(j), j)) & 0xFFFFFFFF,
                7
            )
            let ss2 = ss1 ^ rotl(a, 12)
            let tt1 = (ff(a, b, c, j) &+ d &+ ss2 &+ w1[j]) & 0xFFFFFFFF
            let tt2 = (gg(e, f, g, j) &+ h &+ ss1 &+ w[j]) & 0xFFFFFFFF
            d = c
            c = rotl(b, 9)
            b = a
            a = tt1
            h = g
            g = rotl(f, 19)
            f = e
            e = p0(tt2)
        }

        v[0] ^= a
        v[1] ^= b
        v[2] ^= c
        v[3] ^= d
        v[4] ^= e
        v[5] ^= f
        v[6] ^= g
        v[7] ^= h
    }
}
