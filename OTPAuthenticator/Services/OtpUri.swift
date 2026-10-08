import Foundation

/// 解析二维码 / 外部链接中的 OTP URI。
/// 支持标准 otpauth:// 和 Google 迁移 otpauth-migration:// 两种格式。
struct OtpUri {

    struct ParseResult {
        let entries: [OtpEntry]
        let error: String?
        let otpLike: Bool

        var isSuccess: Bool { error == nil && !entries.isEmpty }
    }

    /// 解析任意扫码文本，自动识别标准 otpauth 与 otpauth-migration
    static func parseAny(_ raw: String?) -> ParseResult {
        guard let raw = raw else {
            return ParseResult(entries: [], error: "二维码内容为空", otpLike: false)
        }
        let s = sanitize(raw)
        if s.isEmpty {
            return ParseResult(entries: [], error: "二维码内容为空", otpLike: false)
        }

        let lower = s.lowercased()
        if lower.hasPrefix("otpauth-migration://") {
            return OtpMigration.parse(s)
        }
        if lower.hasPrefix("otpauth://") {
            return parseStandard(s)
        }
        return ParseResult(entries: [], error: nil, otpLike: false)
    }

    /// 兼容旧调用：解析标准 URI，成功返回第一个账号
    static func parse(_ rawUri: String) -> OtpEntry? {
        let r = parseAny(rawUri)
        return r.isSuccess ? r.entries.first : nil
    }

    // MARK: - 标准 otpauth:// 解析

    private static func parseStandard(_ s: String) -> ParseResult {
        do {
            guard let schemeEnd = s.range(of: "://") else {
                return ParseResult(entries: [], error: "URI 格式错误", otpLike: true)
            }
            let remainder = String(s[schemeEnd.upperBound...])

            // 定位参数区起点
            let queryStart = locateQueryStart(remainder)
            let authorityPath: String
            let queryString: String
            if queryStart >= 0 {
                let idx = remainder.index(remainder.startIndex, offsetBy: queryStart)
                authorityPath = String(remainder[remainder.startIndex..<idx])
                queryString = String(remainder[remainder.index(after: idx)...])
            } else {
                authorityPath = remainder
                queryString = ""
            }

            // host = 第一个 '/' 之前；label = 之后
            let host: String
            let label: String
            if let slash = authorityPath.firstIndex(of: "/") {
                host = String(authorityPath[authorityPath.startIndex..<slash])
                let rawLabel = String(authorityPath[authorityPath.index(after: slash)...])
                label = rawLabel.removingPercentEncoding ?? rawLabel
            } else {
                host = authorityPath
                label = ""
            }

            // 类型
            let type: OtpType
            switch host.trimmingCharacters(in: .whitespaces).lowercased() {
            case "hotp": type = .hotp
            case "totp", "": type = .totp
            default: type = .totp // 容错
            }

            let params = parseQuery(queryString)

            // secret
            var secretParam = params["secret"]
            if secretParam == nil { secretParam = params["key"] }
            guard let sp = secretParam, !sp.isEmpty else {
                return ParseResult(entries: [], error: "二维码中缺少密钥（secret）参数", otpLike: true)
            }
            let secret = OtpEntry.normalizeSecret(sp)
            guard !secret.isEmpty else {
                return ParseResult(entries: [], error: "二维码中的密钥为空", otpLike: true)
            }
            do {
                let keyBytes = try Base32.decode(secret)
                if keyBytes.isEmpty {
                    return ParseResult(entries: [], error: "二维码中的密钥解码后为空", otpLike: true)
                }
            } catch {
                return ParseResult(entries: [], error: "密钥不是有效的 Base32 编码", otpLike: true)
            }

            // issuer / name
            var issuer = cleanIssuer(params["issuer"])
            var name = ""
            if !label.isEmpty {
                let colon = indexOfLabelSeparator(label)
                if colon >= 0 {
                    let ci = label.index(label.startIndex, offsetBy: colon)
                    let labelIssuer = cleanIssuer(String(label[label.startIndex..<ci]))
                    name = String(label[label.index(after: ci)...]).trimmingCharacters(in: .whitespaces)
                    if issuer == nil && labelIssuer != nil {
                        issuer = labelIssuer
                    }
                } else {
                    name = label.trimmingCharacters(in: .whitespaces)
                }
            }
            if name.isEmpty {
                name = issuer ?? "未命名账号"
            }

            // algorithm
            let algo = parseAlgorithm(params["algorithm"])

            // digits
            var digits = 6
            if let dq = params["digits"], let d = Int(dq.trimmingCharacters(in: .whitespaces)) {
                if d == 6 || d == 7 || d == 8 { digits = d }
            }

            // period
            var period = 30
            if let pq = params["period"], let p = Int(pq.trimmingCharacters(in: .whitespaces)) {
                if p >= 1 && p <= 600 { period = p }
            }

            // counter
            var counter: Int64? = nil
            if let cq = params["counter"], let c = Int64(cq.trimmingCharacters(in: .whitespaces)) {
                counter = c
            }
            if type == .hotp && counter == nil { counter = 0 }
            if let c = counter, c < 0 { counter = 0 }

            let entry = OtpEntry(
                issuer: issuer,
                name: name,
                secret: secret,
                type: type,
                counter: counter,
                algorithm: algo,
                digits: digits,
                timeStepSeconds: period
            )
            return ParseResult(entries: [entry], error: nil, otpLike: true)
        } catch {
            return ParseResult(entries: [], error: "URI 格式错误：\(error.localizedDescription)", otpLike: true)
        }
    }

    // MARK: - 辅助方法

    private static func locateQueryStart(_ remainder: String) -> Int {
        var paramIdx = indexOfParamStart(remainder, "secret")
        if paramIdx < 0 { paramIdx = indexOfParamStart(remainder, "key") }
        if paramIdx > 0 {
            let chars = Array(remainder)
            for i in (0..<paramIdx).reversed() {
                if chars[i] == "?" || chars[i] == "&" { return i }
            }
        }
        if let r = remainder.firstIndex(of: "?") {
            return remainder.distance(from: remainder.startIndex, to: r)
        }
        return -1
    }

    private static func indexOfParamStart(_ text: String, _ name: String) -> Int {
        let lower = text.lowercased()
        let needle = name.lowercased() + "="
        var searchRange = lower.startIndex..<lower.endIndex
        while let range = lower.range(of: needle, range: searchRange) {
            let idx = lower.distance(from: lower.startIndex, to: range.lowerBound)
            if idx == 0 { return 0 }
            let chars = Array(text)
            if idx > 0 && idx < chars.count {
                let prev = chars[idx - 1]
                if prev == "?" || prev == "&" { return idx }
            }
            searchRange = range.upperBound..<lower.endIndex
        }
        return -1
    }

    private static func indexOfLabelSeparator(_ label: String) -> Int {
        let half = label.firstIndex(of: ":")
        let full = label.firstIndex(of: "：")
        let h = half.map { label.distance(from: label.startIndex, to: $0) } ?? -1
        let f = full.map { label.distance(from: label.startIndex, to: $0) } ?? -1
        if h < 0 { return f }
        if f < 0 { return h }
        return min(h, f)
    }

    private static func cleanIssuer(_ raw: String?) -> String? {
        guard let t = raw?.trimmingCharacters(in: .whitespaces), !t.isEmpty else { return nil }
        if t.contains("?") { return nil }
        return t
    }

    private static func parseQuery(_ queryString: String) -> [String: String] {
        var map = [String: String]()
        guard !queryString.isEmpty else { return map }
        let q = queryString.replacingOccurrences(of: "&amp;", with: "&")
        for pair in q.split(separator: "&") {
            let ps = String(pair)
            if ps.isEmpty { continue }
            if let eq = ps.firstIndex(of: "=") {
                let key = String(ps[ps.startIndex..<eq])
                let value = String(ps[ps.index(after: eq)...])
                let decodedKey = (key.removingPercentEncoding ?? key).trimmingCharacters(in: .whitespaces).lowercased()
                let decodedValue = value.removingPercentEncoding ?? value
                map[decodedKey] = decodedValue
            } else {
                map[ps.lowercased()] = ""
            }
        }
        return map
    }

    private static func parseAlgorithm(_ raw: String?) -> HashAlgorithm {
        HashAlgorithm.fromString(raw)
    }

    private static func sanitize(_ raw: String) -> String {
        var s = raw
        s = s.replacingOccurrences(of: "\u{FEFF}", with: "")
        s = s.replacingOccurrences(of: "[\\u{200B}-\\u{200D}\\u{2060}]", with: "", options: .regularExpression)
        s = s.replacingOccurrences(of: "[\\x00-\\x1F\\x7F]", with: "", options: .regularExpression)
        return s.trimmingCharacters(in: .whitespaces)
    }

    // MARK: - 反向生成 URI

    static func toUri(_ entry: OtpEntry) -> String {
        var sb = "otpauth://"
        sb += entry.type.rawValue + "/"
        if let issuer = entry.issuer, !issuer.isEmpty {
            sb += issuer.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? issuer
            sb += ":"
        }
        sb += entry.name.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? entry.name
        sb += "?secret=\(entry.secret)"
        if let issuer = entry.issuer, !issuer.isEmpty {
            sb += "&issuer=\(issuer.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? issuer)"
        }
        sb += "&algorithm=\(entry.algorithm.canonical)"
        sb += "&digits=\(entry.digits)"
        if entry.type == .totp {
            sb += "&period=\(entry.timeStepSeconds)"
        } else if let counter = entry.counter {
            sb += "&counter=\(counter)"
        }
        return sb
    }
}
