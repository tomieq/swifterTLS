import Crypto
import Foundation
import SwiftExtensions
import Swifter

public class TLSSocket: SecureSocket {
    private static let configurationLock = NSLock()
    private static var configuredTLSConfiguration: TLSConfiguration?

    private let socket: Socket
    private var readCipher: TLS13CipherState?
    private var writeCipher: TLS13CipherState?
    private var plaintextBuffer = Data()

    public let id: UUID = UUID()
    public var raw: Socket {
        socket
    }

    public static func configure(_ configuration: TLSConfiguration) {
        configurationLock.lock()
        configuredTLSConfiguration = configuration
        configurationLock.unlock()
    }

    public required init(_ socket: Socket) {
        self.socket = socket
        do {
            try performHandshake()
        } catch {
            print("TLS handshake failed: \(error)")
            socket.close()
        }
    }

    private func performHandshake() throws {
        let clientHello = try ClientHello(socket)
        try validate(clientHello)

        let serverKeySharePrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let serverKeySharePublicKey = serverKeySharePrivateKey.publicKey.rawRepresentation
        let serverHello = ServerHello(
            recordVersion: .v1_2,
            serverHelloVersion: .v1_2,
            random: Data.random(length: 32),
            sessionID: clientHello.sessionID,
            chosenCipher: .TLS_AES_128_GCM_SHA256,
            compressionMethod: .null,
            extensions: [
                TLSExtension(type: ExtensionName.supportedVersions.data, body: TLSVersion.v1_3.data),
                TLSExtension(
                    type: ExtensionName.keyShare.data,
                    body: KeyNamedGroup.x25519.data
                        .appending(asTwoBytes: serverKeySharePublicKey.count)
                        .appending(serverKeySharePublicKey)
                )
            ]
        )
        try socket.writeData(serverHello.data)

        let clientPublicKeyData = try clientHello.clientKeys
            .first { $0.namedGroup == .x25519 }
            .map { $0.key }
            .orThrow(TLS13Error.unsupportedKeyShare)
        let clientPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: clientPublicKeyData)
        let sharedSecret = try serverKeySharePrivateKey.sharedSecretFromKeyAgreement(with: clientPublicKey)

        var transcript = clientHello.handshakeData + serverHello.handshakeData
        let handshakeSecrets = TLS13KeySchedule.handshakeTrafficSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: TLS13KeySchedule.transcriptHash(transcript)
        )
        var clientHandshakeCipher = TLS13CipherState(keySet: TLS13KeySchedule.keySet(trafficSecret: handshakeSecrets.client))
        var serverHandshakeCipher = TLS13CipherState(keySet: TLS13KeySchedule.keySet(trafficSecret: handshakeSecrets.server))

        let tlsConfiguration = try Self.currentConfiguration()
        let certificatePrivateKey = try P256.Signing.PrivateKey(derRepresentation: PEMDecoder.decode(tlsConfiguration.privateKeyPEM))
        let certificateDER = try PEMDecoder.decode(tlsConfiguration.certificatePEM)

        let encryptedExtensions = TLS13HandshakeMessage.encryptedExtensions()
        try sendEncryptedHandshake(encryptedExtensions, using: &serverHandshakeCipher)
        transcript.append(encryptedExtensions)

        let certificate = TLS13HandshakeMessage.certificate(derCertificate: certificateDER)
        try sendEncryptedHandshake(certificate, using: &serverHandshakeCipher)
        transcript.append(certificate)

        let certificateVerify = try TLS13HandshakeMessage.certificateVerify(
            privateKey: certificatePrivateKey,
            transcriptHash: TLS13KeySchedule.transcriptHash(transcript)
        )
        try sendEncryptedHandshake(certificateVerify, using: &serverHandshakeCipher)
        transcript.append(certificateVerify)

        let serverFinished = TLS13HandshakeMessage.finished(
            verifyData: TLS13KeySchedule.finishedVerifyData(
                trafficSecret: handshakeSecrets.server,
                transcriptHash: TLS13KeySchedule.transcriptHash(transcript)
            )
        )
        try sendEncryptedHandshake(serverFinished, using: &serverHandshakeCipher)
        transcript.append(serverFinished)

        let applicationSecrets = TLS13KeySchedule.applicationTrafficSecrets(
            handshakeSecret: handshakeSecrets.handshakeSecret,
            transcriptHash: TLS13KeySchedule.transcriptHash(transcript)
        )

        let clientFinished = try readEncryptedHandshake(using: &clientHandshakeCipher)
        try verifyClientFinished(clientFinished, trafficSecret: handshakeSecrets.client, transcript: transcript)
        transcript.append(clientFinished)

        readCipher = TLS13CipherState(keySet: TLS13KeySchedule.keySet(trafficSecret: applicationSecrets.client))
        writeCipher = TLS13CipherState(keySet: TLS13KeySchedule.keySet(trafficSecret: applicationSecrets.server))
    }

    private func validate(_ clientHello: ClientHello) throws {
        guard try clientHello.supportedVersions.contains(.v1_3) else {
            throw TLS13Error.missingExtension(.supportedVersions)
        }
        guard clientHello.supportedCiphers.contains(.TLS_AES_128_GCM_SHA256) else {
            throw TLS13Error.unsupportedCipherSuite
        }
        guard try clientHello.clientKeys.contains(where: { $0.namedGroup == .x25519 }) else {
            throw TLS13Error.unsupportedKeyShare
        }
        guard try clientHello.signatureAlgorithms.contains(TLS13HandshakeMessage.ecdsaSecp256r1Sha256) else {
            throw TLS13Error.unsupportedSignatureScheme
        }
    }

    private static func currentConfiguration() throws -> TLSConfiguration {
        configurationLock.lock()
        defer { configurationLock.unlock() }
        guard let configuredTLSConfiguration else {
            throw TLS13Error.missingConfiguration
        }
        return configuredTLSConfiguration
    }

    private func sendEncryptedHandshake(_ handshakeMessage: Data, using cipher: inout TLS13CipherState) throws {
        let record = try cipher.seal(handshakeMessage, contentType: .handshake)
        try socket.writeData(record.data)
    }

    private func readEncryptedHandshake(using cipher: inout TLS13CipherState) throws -> Data {
        while true {
            let record = try readTLSRecordSkippingCompatibilityRecords()
            let opened = try cipher.open(record)
            if opened.contentType == .handshake {
                return opened.plaintext
            }
        }
    }

    private func verifyClientFinished(_ finishedMessage: Data, trafficSecret: SymmetricKey, transcript: Data) throws {
        var body = finishedMessage
        guard body.consume(bytes: 1) == HandshakeType.finished.rawValue.data else {
            throw TLS13Error.invalidFinished
        }
        let length = try body.consume(bytes: 3).int
        guard length == body.count else {
            throw TLS13Error.invalidFinished
        }
        let expected = TLS13KeySchedule.finishedVerifyData(
            trafficSecret: trafficSecret,
            transcriptHash: TLS13KeySchedule.transcriptHash(transcript)
        )
        guard body == expected else {
            throw TLS13Error.invalidFinished
        }
    }

    private func readTLSRecordSkippingCompatibilityRecords() throws -> Record {
        while true {
            let record = try Record(socket: socket)
            if record.recordType == .changeCipherSpec, record.body == Data([1]) {
                continue
            }
            return record
        }
    }

    public func read() throws -> UInt8 {
        while plaintextBuffer.isEmpty {
            try readApplicationData()
        }
        return plaintextBuffer.consume(bytes: 1).first!
    }

    public func readLine() throws -> String {
        var characters = ""
        var byte: UInt8 = 0
        repeat {
            byte = try read()
            if byte > 13 {
                characters.append(Character(UnicodeScalar(byte)))
            }
        } while byte != 10
        return characters
    }

    public func read(length: Int) throws -> [UInt8] {
        while plaintextBuffer.count < length {
            try readApplicationData()
        }
        return Array(plaintextBuffer.consume(bytes: length))
    }

    private func readApplicationData() throws {
        guard var cipher = readCipher else {
            throw TLS13Error.handshakeNotComplete
        }
        let record = try readTLSRecordSkippingCompatibilityRecords()
        let opened = try cipher.open(record)
        readCipher = cipher
        switch opened.contentType {
        case .applicationData:
            plaintextBuffer.append(opened.plaintext)
        case .alert:
            close()
            throw TLS13Error.invalidEncryptedRecord
        default:
            break
        }
    }

    public func writeUTF8(_ string: String) throws {
        try writeData(Data(string.utf8))
    }

    public func writeUInt8(_ data: [UInt8]) throws {
        try writeData(Data(data))
    }

    public func writeUInt8(_ data: ArraySlice<UInt8>) throws {
        try writeData(Data(data))
    }

    public func writeData(_ data: Data) throws {
        guard var cipher = writeCipher else {
            throw TLS13Error.handshakeNotComplete
        }
        var offset = 0
        while offset < data.count {
            let chunkEnd = min(offset + 16_384, data.count)
            let record = try cipher.seal(data[offset..<chunkEnd], contentType: .applicationData)
            try socket.writeData(record.data)
            offset = chunkEnd
        }
        writeCipher = cipher
    }

    public func writeData(_ data: NSData) throws {
        try writeData(data as Data)
    }

    public func writeFile(_ file: String.File) throws {
        var buffer = [UInt8](repeating: 0, count: 16_384)
        while true {
            let count = try file.read(&buffer)
            if count == 0 {
                return
            }
            try writeUInt8(buffer.prefix(count))
        }
    }

    public func close() {
        socket.close()
    }

    public var peerIP: String? {
        nil
    }
}
