import SwiftUI

/// OTP 列表卡片，与安卓版 item_otp.xml 完全一致（Material Design 3 风格）
struct OtpTileView: View {
    let entry: OtpEntry
    let code: String
    let progress: Double          // 0~1，安卓版: 1 - remaining/step（随时间填充）
    let metaText: String          // "13s" 或 "counter 0"
    let onCopy: () -> Void
    let onHotpRefresh: () -> Void
    let onDelete: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // 顶部行：头像 + 名称 + 删除
            HStack(spacing: 12) {
                // 头像 44x44 圆形
                ZStack {
                    Circle()
                        .fill(Color.mdPrimaryContainer)
                        .frame(width: 44, height: 44)
                    Text(entry.initials)
                        .font(.system(size: 16, weight: .bold))
                        .foregroundColor(Color.mdOnPrimaryContainer)
                }

                // 名称 + 副标题
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.system(size: 16, weight: .bold))
                        .foregroundColor(Color.mdPrimary)
                        .lineLimit(1)

                    Text(subtitle)
                        .font(.system(size: 12))
                        .foregroundColor(Color.mdOutline)
                        .lineLimit(1)
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                // 删除按钮
                Button(action: onDelete) {
                    Image(systemName: "trash")
                        .font(.system(size: 20))
                        .foregroundColor(Color.mdError)
                        .frame(width: 40, height: 40)
                }
            }

            // 动态口令（居中、等宽、大号）
            Text(formattedCode)
                .font(.system(size: 32, weight: .bold, design: .monospaced))
                .foregroundColor(code == "------" ? Color.mdOutline.opacity(0.4) : Color.mdPrimary)
                .tracking(2)
                .frame(maxWidth: .infinity)
                .padding(.top, 10)
                .onTapGesture(perform: onCopy)

            // 底部行：进度条 + meta + 刷新按钮
            HStack(spacing: 8) {
                if entry.type == .totp {
                    // 进度条（安卓版随时间填充）
                    GeometryReader { geo in
                        ZStack(alignment: .leading) {
                            RoundedRectangle(cornerRadius: 2)
                                .fill(Color.mdSurfaceVariant)
                                .frame(height: 4)
                            RoundedRectangle(cornerRadius: 2)
                                .fill(Color.mdPrimary)
                                .frame(width: geo.size.width * progress, height: 4)
                                .animation(.linear(duration: 0.5), value: progress)
                        }
                    }
                    .frame(height: 4)
                }

                // meta 文本
                Text(metaText)
                    .font(.system(size: 13))
                    .foregroundColor(Color.mdOutline)

                // HOTP 刷新按钮
                if entry.type == .hotp {
                    Button(action: onHotpRefresh) {
                        Image(systemName: "arrow.clockwise")
                            .font(.system(size: 18))
                            .foregroundColor(Color.mdPrimary)
                            .frame(width: 36, height: 36)
                    }
                }
            }
            .padding(.top, 10)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 14)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(.secondarySystemGroupedBackground))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 16)
                .stroke(Color.mdOutlineVariant, lineWidth: 1)
        )
        .padding(.horizontal, 12)
        .padding(.vertical, 4)
        .contentShape(Rectangle())
        .onTapGesture(perform: onCopy)
    }

    // MARK: - 辅助

    private var title: String {
        if entry.name.isEmpty {
            return entry.issuer?.isEmpty == false ? entry.issuer! : "未命名账号"
        }
        return entry.name
    }

    private var subtitle: String {
        "\(entry.type.displayName) · \(entry.algorithm.canonical) · \(entry.digits)位"
    }

    /// 安卓版：从中间分割加空格，如 "123456" → "123 456"
    private var formattedCode: String {
        guard code != "------", code.count > 4 else { return code }
        let mid = code.count / 2
        let idx = code.index(code.startIndex, offsetBy: mid)
        return "\(code[code.startIndex..<idx]) \(code[idx...])"
    }
}
