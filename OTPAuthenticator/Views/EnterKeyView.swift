import SwiftUI

/// 手动输入密钥添加账号
struct EnterKeyView: View {
    @EnvironmentObject var viewModel: OtpViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var issuer = ""
    @State private var accountName = ""
    @State private var secret = ""
    @State private var type: OtpType = .totp
    @State private var algorithm: HashAlgorithm = .sha1
    @State private var digits = 6
    @State private var counter = ""
    @State private var showError = false
    @State private var errorMessage = ""

    var body: some View {
        NavigationView {
            Form {
                Section("账号信息") {
                    TextField("颁发者（可选，如 Google）", text: $issuer)
                        .autocapitalization(.none)
                    TextField("账号名称", text: $accountName)
                        .autocapitalization(.none)
                }

                Section("密钥") {
                    TextField("Base32 密钥", text: $secret)
                        .autocapitalization(.none)
                        .font(.system(.body, design: .monospaced))
                }

                Section("类型与算法") {
                    Picker("类型", selection: $type) {
                        Text("TOTP（时间）").tag(OtpType.totp)
                        Text("HOTP（计数器）").tag(OtpType.hotp)
                    }

                    Picker("算法", selection: $algorithm) {
                        Text("SHA1").tag(HashAlgorithm.sha1)
                        Text("SHA256").tag(HashAlgorithm.sha256)
                        Text("SHA512").tag(HashAlgorithm.sha512)
                        Text("SHA224").tag(HashAlgorithm.sha224)
                        Text("SHA384").tag(HashAlgorithm.sha384)
                        Text("MD5").tag(HashAlgorithm.md5)
                        Text("SM3").tag(HashAlgorithm.sm3)
                        Text("SM4").tag(HashAlgorithm.cbcsm4)
                    }

                    Picker("位数", selection: $digits) {
                        Text("6 位").tag(6)
                        Text("7 位").tag(7)
                        Text("8 位").tag(8)
                    }

                    if type == .hotp {
                        TextField("初始计数器（默认 0）", text: $counter)
                            .keyboardType(.numberPad)
                    }
                }

                Section {
                    Button(action: save) {
                        Text("添加")
                            .frame(maxWidth: .infinity)
                            .foregroundColor(.white)
                    }
                    .listRowBackground(Color.blue)
                }
            }
            .navigationTitle("手动添加")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("取消") { dismiss() }
                }
            }
            .alert("错误", isPresented: $showError) {
                Button("确定", role: .cancel) {}
            } message: {
                Text(errorMessage)
            }
        }
    }

    private func save() {
        let trimmedSecret = secret.trimmingCharacters(in: .whitespaces)
        guard !trimmedSecret.isEmpty else {
            errorMessage = "请输入密钥"
            showError = true
            return
        }
        do {
            _ = try Base32.decode(OtpEntry.normalizeSecret(trimmedSecret))
        } catch {
            errorMessage = "密钥不是有效的 Base32 编码"
            showError = true
            return
        }

        let counterVal = Int64(counter) ?? 0
        let entry = OtpEntry(
            issuer: issuer.isEmpty ? nil : issuer,
            name: accountName.isEmpty ? "未命名账号" : accountName,
            secret: trimmedSecret,
            type: type,
            counter: type == .hotp ? counterVal : nil,
            algorithm: algorithm,
            digits: digits,
            timeStepSeconds: 30
        )
        viewModel.add(entry)
        dismiss()
    }
}
