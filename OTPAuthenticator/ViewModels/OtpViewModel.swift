import Foundation
import SwiftUI
import Combine

/// 全局 OTP 状态管理：账号列表、实时刷新口令、增删改
@MainActor
final class OtpViewModel: ObservableObject {

    @Published var entries: [OtpEntry] = []
    @Published var currentCodes: [String: String] = [:]   // entry.id → 当前口令
    @Published var progress: Double = 0.0                 // 倒计时进度 0~1
    @Published var secondsRemaining: Int = 30

    private let store = OtpStore.shared
    private var timer: Timer?

    init() {
        load()
        startTimer()
    }

    deinit {
        timer?.invalidate()
    }

    // MARK: - 数据加载

    func load() {
        entries = store.getAll()
        refreshCodes()
    }

    // MARK: - 增删改

    func add(_ entry: OtpEntry) {
        store.save(entry)
        load()
    }

    func addEntries(_ newEntries: [OtpEntry]) {
        for e in newEntries { store.save(e) }
        load()
    }

    func delete(_ entry: OtpEntry) {
        store.delete(entry.id)
        load()
    }

    func delete(at offsets: IndexSet) {
        for idx in offsets {
            if idx < entries.count {
                store.delete(entries[idx].id)
            }
        }
        load()
    }

    func incrementHotp(_ entry: OtpEntry) {
        store.incrementHotpCounter(entry.id)
        load()
    }

    // MARK: - 口令计算

    func currentCode(for entry: OtpEntry) -> String {
        if let cached = currentCodes[entry.id] { return cached }
        return computeCode(entry)
    }

    /// 进度条比例（安卓版：随时间填充，0→1）
    func progress(for entry: OtpEntry) -> Double {
        guard entry.type == .totp else { return 0 }
        let step = entry.timeStepSeconds > 0 ? entry.timeStepSeconds : 30
        let now = Date().timeIntervalSince1970
        let elapsed = now.truncatingRemainder(dividingBy: Double(step))
        return min(1, max(0, elapsed / Double(step)))
    }

    /// meta 文本：TOTP 显示 "13s"，HOTP 显示 "counter 0"
    func metaText(for entry: OtpEntry) -> String {
        if entry.type == .totp {
            let step = entry.timeStepSeconds > 0 ? entry.timeStepSeconds : 30
            let now = Date().timeIntervalSince1970
            let elapsed = now.truncatingRemainder(dividingBy: Double(step))
            let remaining = Double(step) - elapsed
            let secs = Int(ceil(remaining))
            return "\(secs)s"
        } else {
            return "counter \(entry.counter ?? 0)"
        }
    }

    private func computeCode(_ entry: OtpEntry) -> String {
        do {
            let secret = try entry.decodedSecret()
            if entry.type == .totp {
                let now = Int64(Date().timeIntervalSince1970)
                return try PasscodeGenerator.totp(
                    unixSeconds: now,
                    secret: secret,
                    algorithm: entry.algorithm,
                    digits: entry.digits,
                    timeStepSeconds: entry.timeStepSeconds
                )
            } else {
                let counter = entry.counter ?? 0
                return try PasscodeGenerator.hotp(
                    counter: counter,
                    secret: secret,
                    algorithm: entry.algorithm,
                    digits: entry.digits
                )
            }
        } catch {
            return "------"
        }
    }

    private func refreshCodes() {
        var codes = [String: String]()
        for entry in entries {
            codes[entry.id] = computeCode(entry)
        }
        currentCodes = codes
        updateProgress()
    }

    private func updateProgress() {
        let step = 30
        let now = Int(Date().timeIntervalSince1970)
        let elapsed = now % step
        secondsRemaining = step - elapsed
        progress = Double(secondsRemaining) / Double(step)
    }

    // MARK: - 定时器

    private func startTimer() {
        let t = Timer(timeInterval: 1.0, repeats: true) { [weak self] _ in
            self?.tick()
        }
        RunLoop.main.add(t, forMode: .common)
        timer = t
    }

    private func tick() {
        let step = 30
        let now = Int(Date().timeIntervalSince1970)
        let elapsed = now % step
        secondsRemaining = step - elapsed
        progress = Double(secondsRemaining) / Double(step)
        // 每 30 秒刷新一次口令
        if elapsed == 0 {
            refreshCodes()
        }
    }

    func forceRefresh() {
        refreshCodes()
    }
}
