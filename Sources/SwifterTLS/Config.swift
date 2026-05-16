public struct TLSConfiguration: Sendable {
    public let privateKeyPEM: String
    public let certificatePEM: String

    public init(privateKeyPEM: String, certificatePEM: String) {
        self.privateKeyPEM = privateKeyPEM
        self.certificatePEM = certificatePEM
    }
}
