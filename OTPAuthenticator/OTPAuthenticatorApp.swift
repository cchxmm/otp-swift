import SwiftUI

@main
struct OTPAuthenticatorApp: App {
    @StateObject private var viewModel = OtpViewModel()

    var body: some Scene {
        WindowGroup {
            HomeView()
                .environmentObject(viewModel)
        }
    }
}
