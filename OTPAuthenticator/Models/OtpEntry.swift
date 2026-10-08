import Foundation

/// OTP 账号数据模型，与安卓版 OtpEntry.java 完全对应
struct OtpEntry: Codable, Identifiable, Equatable {
    let id: String
    var issuer: String?
    var name: String
    let secret: String        // Base32 编码（无空格、无 padding）
    let type: OtpType
    var counter: Int64?       // 仅 HOTP 使用
    var algorithm: HashAlgorithm
    var digits: Int
    var timeStepSeconds: Int
    let createdAt: Int64

    init(
        id: String? = nil,
        issuer: String? = nil,
        name: String = "",
        secret: String,
        type: OtpType = .totp,
        counter: Int64? = nil,
        algorithm: HashAlgorithm = .sha1,
        digits: Int = 6,
        timeStepSeconds: Int = 30,
        createdAt: Int64 = Int64(Date().timeIntervalSince1970 * 1000)
    ) {
        self.id = id ?? UUID().uuidString
        self.issuer = issuer
        self.name = name
        self.secret = Self.normalizeSecret(secret)
        self.type = type
        self.counter = type == .hotp ? (counter ?? 0) : nil
        self.algorithm = algorithm
        self.digits = digits <= 0 ? 6 : digits
        self.timeStepSeconds = timeStepSeconds <= 0 ? 30 : timeStepSeconds
        self.createdAt = createdAt <= 0 ? Int64(Date().timeIntervalSince1970 * 1000) : createdAt
    }

    /// 便捷工厂方法：新建账号
    static func create(
        issuer: String?,
        name: String,
        secret: String,
        type: OtpType,
        counter: Int64,
        algorithm: HashAlgorithm,
        digits: Int
    ) -> OtpEntry {
        OtpEntry(
            issuer: issuer,
            name: name,
            secret: secret,
            type: type,
            counter: type == .hotp ? counter : nil,
            algorithm: algorithm,
            digits: digits,
            timeStepSeconds: 30
        )
    }

    /// 去除空格、破折号、下划线、padding，转大写
    static func normalizeSecret(_ raw: String) -> String {
        var s = raw
        s = s.replacingOccurrences(of: "\\s+", with: "", options: .regularExpression)
        s = s.replacingOccurrences(of: "-", with: "")
        s = s.replacingOccurrences(of: "_", with: "")
        s = s.replacingOccurrences(of: "=", with: "")
        return s.uppercased()
    }

    /// Base32 解码后的原始密钥字节
    func decodedSecret() throws -> [UInt8] {
        try Base32.decode(secret)
    }

    /// 显示名称："Issuer: Name" 或仅 "Name"
    var displayName: String {
        if let issuer = issuer, !issuer.isEmpty {
            return name.isEmpty ? issuer : "\(issuer): \(name)"
        }
        return name.isEmpty ? "(未命名)" : name
    }

    /// 两字母头像
    var initials: String {
        let src = (issuer?.isEmpty == false ? issuer : name) ?? "?"
        let trimmed = src.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty { return "?" }
        if let sp = trimmed.firstIndex(of: " "), sp != trimmed.startIndex {
            let after = trimmed.index(after: sp)
            if after < trimmed.endIndex {
                return "\(trimmed.first!)\(trimmed[after])".uppercased()
            }
        }
        return String(trimmed.prefix(2)).uppercased()
    }

    static func == (lhs: OtpEntry, rhs: OtpEntry) -> Bool {
        lhs.id == rhs.id
    }
}
