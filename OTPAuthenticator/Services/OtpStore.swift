import Foundation

/// 持久化存储 OTP 账号，使用 UserDefaults + JSON。
/// 与安卓版 OtpStore.java 对应。
final class OtpStore {

    static let shared = OtpStore()

    private let defaults = UserDefaults.standard
    private let keyEntries = "otp_entries_json"

    private init() {}

    // MARK: - 读取

    func getAll() -> [OtpEntry] {
        guard let json = defaults.string(forKey: keyEntries),
              let data = json.data(using: .utf8) else {
            return []
        }
        do {
            let decoder = JSONDecoder()
            return try decoder.decode([OtpEntry].self, from: data)
        } catch {
            return []
        }
    }

    // MARK: - 写入

    func save(_ entry: OtpEntry) {
        var all = getAll()
        if let idx = all.firstIndex(where: { $0.id == entry.id }) {
            all[idx] = entry
        } else {
            all.append(entry)
        }
        persist(all)
    }

    func delete(_ id: String) {
        let all = getAll().filter { $0.id != id }
        persist(all)
    }

    func replaceAll(_ entries: [OtpEntry]) {
        persist(entries)
    }

    /// HOTP：计数器 +1
    func incrementHotpCounter(_ id: String) {
        var all = getAll()
        for i in all.indices {
            if all[i].id == id, all[i].type == .hotp, all[i].counter != nil {
                all[i].counter! += 1
            }
        }
        persist(all)
    }

    // MARK: - 私有

    private func persist(_ entries: [OtpEntry]) {
        do {
            let encoder = JSONEncoder()
            let data = try encoder.encode(entries)
            let json = String(data: data, encoding: .utf8)
            defaults.set(json, forKey: keyEntries)
        } catch {
            // 忽略编码错误
        }
    }
}
