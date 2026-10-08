import SwiftUI

/// 主页，与安卓版 activity_main.xml 一致：列表 + FAB + 底部弹窗
struct HomeView: View {
    @EnvironmentObject var viewModel: OtpViewModel
    @State private var showingAddSheet = false
    @State private var showingScan = false
    @State private var showingEnterKey = false
    @State private var toastMessage: String?

    var body: some View {
        ZStack {
            Color.mdBackground.ignoresSafeArea()

            if viewModel.entries.isEmpty {
                emptyState
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(viewModel.entries) { entry in
                            OtpTileView(
                                entry: entry,
                                code: viewModel.currentCode(for: entry),
                                progress: viewModel.progress(for: entry),
                                metaText: viewModel.metaText(for: entry),
                                onCopy: { copyCode(entry) },
                                onHotpRefresh: { viewModel.incrementHotp(entry) },
                                onDelete: { viewModel.delete(entry) }
                            )
                        }
                    }
                    .padding(.top, 8)
                    .padding(.bottom, 96)
                }
            }

            // FAB 右下角
            VStack {
                Spacer()
                HStack {
                    Spacer()
                    Button(action: { showingAddSheet = true }) {
                        Image(systemName: "plus")
                            .font(.system(size: 24, weight: .medium))
                            .foregroundColor(.white)
                            .frame(width: 56, height: 56)
                            .background(Color.mdPrimary)
                            .clipShape(Circle())
                            .shadow(color: .black.opacity(0.2), radius: 4, y: 2)
                    }
                    .padding(.trailing, 16)
                    .padding(.bottom, 16)
                }
            }
        }
        .navigationTitle("动态口令")
        .navigationBarTitleDisplayMode(.inline)
        .confirmationDialog("添加账号", isPresented: $showingAddSheet, titleVisibility: .visible) {
            Button("扫描二维码") { showingScan = true }
            Button("手动输入密钥") { showingEnterKey = true }
            Button("取消", role: .cancel) {}
        }
        .sheet(isPresented: $showingScan) {
            ScanView().environmentObject(viewModel)
        }
        .sheet(isPresented: $showingEnterKey) {
            EnterKeyView().environmentObject(viewModel)
        }
        .overlay {
            if let msg = toastMessage {
                VStack {
                    Spacer()
                    Text(msg)
                        .font(.system(size: 14, weight: .medium))
                        .foregroundColor(.white)
                        .padding(.horizontal, 20)
                        .padding(.vertical, 12)
                        .background(Color.black.opacity(0.75))
                        .cornerRadius(24)
                        .padding(.bottom, 100)
                }
                .transition(.opacity)
                .onAppear {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                        withAnimation { toastMessage = nil }
                    }
                }
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.shield")
                .font(.system(size: 80))
                .foregroundColor(.gray.opacity(0.4))
            Text("还没有动态口令")
                .font(.system(size: 22, weight: .semibold))
                .foregroundColor(Color.mdOnSurface)
            Text("点击右下角 + 添加账号")
                .font(.system(size: 14))
                .foregroundColor(Color.mdOutline)
        }
    }

    private func copyCode(_ entry: OtpEntry) {
        let code = viewModel.currentCode(for: entry).replacingOccurrences(of: " ", with: "")
        UIPasteboard.general.string = code
        withAnimation { toastMessage = "已复制到剪贴板" }
    }
}
