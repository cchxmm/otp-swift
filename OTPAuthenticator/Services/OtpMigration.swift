import Foundation

/// 解析 Google Authenticator "导出账号"二维码的迁移 URI：
/// otpauth-migration://offline?data={URL-safe Base64 的 protobuf}
enum OtpMigration {

    static func parse(_ uri: String) -> OtpUri.ParseResult {
        do {
            guard let data = extractDataParam(uri), !data.isEmpty else {
                return OtpUri.ParseResult(entries: [], error: "迁移码中缺少 data 参数", otpLike: true)
            }
            guard let payload = decodeUrlSafeBase64(data), !payload.isEmpty else {
                return OtpUri.ParseResult(entries: [], error: "迁移码 Base64 解码失败", otpLike: true)
            }
            let entries = try parsePayload(payload)
            if entries.isEmpty {
                return OtpUri.ParseResult(entries: [], error: "迁移码中没有可导入的账号", otpLike: true)
            }
            return OtpUri.ParseResult(entries: entries, error: nil, otpLike: true)
        } catch {
            return OtpUri.ParseResult(entries: [], error: "迁移码解析失败：\(error.localizedDescription)", otpLike: true)
        }
    }

    // MARK: - 私有

    private static func extractDataParam(_ uri: String) -> String? {
        guard let qIdx = uri.firstIndex(of: "?") else { return nil }
        var query = String(uri[uri.index(after: qIdx)...])
        query = query.replacingOccurrences(of: "&amp;", with: "&")
        for pair in query.split(separator: "&") {
            let ps = String(pair)
            if ps.hasPrefix("data=") {
                return String(ps.dropFirst(5))
            }
        }
        return nil
    }

    private static func decodeUrlSafeBase64(_ raw: String) -> [UInt8]? {
        var s = raw.trimmingCharacters(in: .whitespaces)
        s = s.replacingOccurrences(of: "-", with: "+")
        s = s.replacingOccurrences(of: "_", with: "/")
        let mod = s.count % 4
        if mod == 2 { s += "==" }
        else if mod == 3 { s += "=" }
        guard let data = Data(base64Encoded: s) else { return nil }
        return [UInt8](data)
    }

    private static func parsePayload(_ data: [UInt8]) throws -> [OtpEntry] {
        var entries = [OtpEntry]()
        var r = ProtoReader(data: data)
        while r.hasMore() {
            let tag = try r.readVarint()
            let field = Int(tag >> 3)
            let wireType = Int(tag & 0x07)
            if field == 1 && wireType == 2 {
                let sub = try r.readBytes()
                if let e = try parseOtpParameters(sub) {
                    entries.append(e)
                }
            } else {
                try r.skipField(wireType)
            }
        }
        return entries
    }

    private static func parseOtpParameters(_ data: [UInt8]) throws -> OtpEntry? {
        var r = ProtoReader(data: data)
        var secret: [UInt8]?
        var accountName: String?
        var issuer: String?
        var algorithmValue = 0
        var digitsValue = 0
        var typeValue = 0
        var counter: Int64 = 0

        while r.hasMore() {
            let tag = try r.readVarint()
            let field = Int(tag >> 3)
            let wireType = Int(tag & 0x07)
            switch field {
            case 1:
                if wireType == 2 { secret = try r.readBytes() } else { try r.skipField(wireType) }
            case 2:
                accountName = wireType == 2 ? try r.readUtf8() : nil
                if wireType != 2 { try r.skipField(wireType) }
            case 3:
                issuer = wireType == 2 ? try r.readUtf8() : nil
                if wireType != 2 { try r.skipField(wireType) }
            case 4:
                if wireType == 0 { algorithmValue = Int(try r.readVarint()) } else { try r.skipField(wireType) }
            case 5:
                if wireType == 0 { digitsValue = Int(try r.readVarint()) } else { try r.skipField(wireType) }
            case 6:
                if wireType == 0 { typeValue = Int(try r.readVarint()) } else { try r.skipField(wireType) }
            case 7:
                if wireType == 0 { counter = Int64(bitPattern: try r.readVarint()) } else { try r.skipField(wireType) }
            default:
                try r.skipField(wireType)
            }
        }

        guard let secret = secret, !secret.isEmpty else { return nil }

        let secretBase32 = Base32.encode(secret)

        let algo: HashAlgorithm
        switch algorithmValue {
        case 2: algo = .sha256
        case 3: algo = .sha512
        default: algo = .sha1
        }

        let digits: Int
        switch digitsValue {
        case 2: digits = 7
        case 3: digits = 8
        default: digits = 6
        }

        let type: OtpType = typeValue == 1 ? .hotp : .totp
        let counterVal: Int64? = type == .hotp ? counter : nil

        var name = accountName?.trimmingCharacters(in: .whitespaces) ?? ""
        var issuerTrimmed = issuer?.trimmingCharacters(in: .whitespaces)
        if issuerTrimmed?.isEmpty == true { issuerTrimmed = nil }
        if name.isEmpty {
            name = issuerTrimmed ?? "未命名账号"
        }

        return OtpEntry(
            issuer: issuerTrimmed,
            name: name,
            secret: secretBase32,
            type: type,
            counter: counterVal,
            algorithm: algo,
            digits: digits,
            timeStepSeconds: 30
        )
    }
}

// MARK: - 极简 protobuf Reader

private struct ProtoReader {
    let data: [UInt8]
    var pos: Int = 0

    func hasMore() -> Bool { pos < data.count }

    mutating func readVarint() throws -> UInt64 {
        var result: UInt64 = 0
        var shift: UInt64 = 0
        while true {
            guard pos < data.count else {
                throw NSError(domain: "ProtoReader", code: 1,
                              userInfo: [NSLocalizedDescriptionKey: "varint 越界"])
            }
            let b = data[pos]
            pos += 1
            result |= UInt64(b & 0x7F) << shift
            if (b & 0x80) == 0 { break }
            shift += 7
            if shift > 63 {
                throw NSError(domain: "ProtoReader", code: 2,
                              userInfo: [NSLocalizedDescriptionKey: "varint 过长"])
            }
        }
        return result
    }

    mutating func readBytes() throws -> [UInt8] {
        let length = Int(try readVarint())
        guard length >= 0, pos + length <= data.count else {
            throw NSError(domain: "ProtoReader", code: 3,
                          userInfo: [NSLocalizedDescriptionKey: "字节段越界"])
        }
        let out = Array(data[pos..<(pos + length)])
        pos += length
        return out
    }

    mutating func readUtf8() throws -> String {
        let bytes = try readBytes()
        return String(bytes: bytes, encoding: .utf8) ?? ""
    }

    mutating func skipField(_ wireType: Int) throws {
        switch wireType {
        case 0: _ = try readVarint()
        case 1: try advance(8)
        case 2:
            let length = Int(try readVarint())
            try advance(length)
        case 5: try advance(4)
        default:
            throw NSError(domain: "ProtoReader", code: 4,
                          userInfo: [NSLocalizedDescriptionKey: "不支持的 wire type: \(wireType)"])
        }
    }

    private mutating func advance(_ n: Int) throws {
        guard pos + n <= data.count else {
            throw NSError(domain: "ProtoReader", code: 5,
                          userInfo: [NSLocalizedDescriptionKey: "跳过字段越界"])
        }
        pos += n
    }
}
