import SwiftUI
import AVFoundation

/// 扫码添加账号界面：使用摄像头识别二维码
struct ScanView: UIViewControllerRepresentable {
    @EnvironmentObject var viewModel: OtpViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var showAlert = false
    @State private var alertMessage = ""

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    func makeUIViewController(context: Context) -> ScannerVC {
        let vc = ScannerVC()
        vc.delegate = context.coordinator
        return vc
    }

    func updateUIViewController(_ uiViewController: ScannerVC, context: Context) {}

    // MARK: - Coordinator

    class Coordinator: NSObject, ScannerVCDelegate {
        var parent: ScanView

        init(_ parent: ScanView) {
            self.parent = parent
        }

        func didScanCode(_ code: String) {
            let result = OtpUri.parseAny(code)
            DispatchQueue.main.async {
                if result.isSuccess {
                    self.parent.viewModel.addEntries(result.entries)
                    self.parent.dismiss()
                } else if result.otpLike {
                    self.parent.alertMessage = result.error ?? "解析失败"
                    self.parent.showAlert = true
                } else {
                    self.parent.alertMessage = "这不是有效的动态口令二维码"
                    self.parent.showAlert = true
                }
            }
        }

        func didFailWithError(_ error: String) {
            DispatchQueue.main.async {
                self.parent.alertMessage = error
                self.parent.showAlert = true
            }
        }
    }
}

// MARK: - 底层扫码控制器

protocol ScannerVCDelegate: AnyObject {
    func didScanCode(_ code: String)
    func didFailWithError(_ error: String)
}

class ScannerVC: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    weak var delegate: ScannerVCDelegate?
    private var captureSession: AVCaptureSession?
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var handled = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        setupScanner()

        // 顶部提示
        let hint = UILabel()
        hint.text = "将二维码放入框内，自动识别"
        hint.textColor = .white
        hint.font = .systemFont(ofSize: 14)
        hint.textAlignment = .center
        hint.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(hint)
        NSLayoutConstraint.activate([
            hint.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            hint.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 20)
        ])

        // 关闭按钮
        let closeBtn = UIButton(type: .system)
        closeBtn.setImage(UIImage(systemName: "xmark.circle.fill"), for: .normal)
        closeBtn.tintColor = .white
        closeBtn.backgroundColor = UIColor.black.withAlphaComponent(0.5)
        closeBtn.layer.cornerRadius = 20
        closeBtn.translatesAutoresizingMaskIntoConstraints = false
        closeBtn.addTarget(self, action: #selector(closeTapped), for: .touchUpInside)
        view.addSubview(closeBtn)
        NSLayoutConstraint.activate([
            closeBtn.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 16),
            closeBtn.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
            closeBtn.widthAnchor.constraint(equalToConstant: 40),
            closeBtn.heightAnchor.constraint(equalToConstant: 40)
        ])
    }

    @objc private func closeTapped() {
        dismiss(animated: true)
    }

    private func setupScanner() {
        let session = AVCaptureSession()
        guard let device = AVCaptureDevice.default(for: .video) else {
            delegate?.didFailWithError("无法访问摄像头")
            return
        }
        do {
            let input = try AVCaptureDeviceInput(device: device)
            session.addInput(input)
        } catch {
            delegate?.didFailWithError("摄像头初始化失败：\(error.localizedDescription)")
            return
        }

        let output = AVCaptureMetadataOutput()
        if session.canAddOutput(output) {
            session.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            output.metadataObjectTypes = [.qr]
        }

        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.bounds
        view.layer.insertSublayer(preview, at: 0)
        self.previewLayer = preview
        self.captureSession = session

        DispatchQueue.global(qos: .userInitiated).async {
            session.startRunning()
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput,
                        didOutput metadataObjects: [AVMetadataObject],
                        from connection: AVCaptureConnection) {
        guard !handled, let obj = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              let code = obj.stringValue else { return }
        handled = true
        captureSession?.stopRunning()
        delegate?.didScanCode(code)
    }
}
