import Crypto
import Foundation
import SwiftExtensions
import Swifter

public class TLSSocket: SecureSocket {
    private let tlsConfiguration: TLSConfiguration

    private let socket: Socket
    private var readCipher: TLS13CipherState?
    private var writeCipher: TLS13CipherState?
    private var plaintextBuffer = Data()

    public let id: UUID = UUID()
    public var raw: Socket {
        self.socket
    }

    public init?(_ socket: Socket, tlsConfiguration: TLSConfiguration) {
        self.socket = socket
        self.tlsConfiguration = tlsConfiguration
        do {
            try self.performHandshake()
        } catch {
            print("TLS handshake failed: \(error)")
            socket.close()
            return nil
        }
    }

    private func performHandshake() throws {
        let clientHello = try ClientHello(socket)
        try validate(clientHello)

        let clientKeyShare = try self.selectClientKeyShare(from: clientHello)
        let serverKeyShare = try TLSKeyExchange.serverKeyShare(for: clientKeyShare.namedGroup)
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
                    body: serverKeyShare.namedGroup.data
                        .appending(asTwoBytes: serverKeyShare.publicKey.count)
                        .appending(serverKeyShare.publicKey)
                )
            ]
        )
        try self.socket.writeData(serverHello.data)

        let sharedSecret = try serverKeyShare.sharedSecret(with: clientKeyShare.key)

        var transcript = clientHello.handshakeData + serverHello.handshakeData
        let handshakeSecrets = TLS13KeySchedule.handshakeTrafficSecrets(
            sharedSecret: sharedSecret,
            transcriptHash: TLS13KeySchedule.transcriptHash(transcript)
        )
        var clientHandshakeCipher = TLS13CipherState(keySet: TLS13KeySchedule.keySet(trafficSecret: handshakeSecrets.client))
        var serverHandshakeCipher = TLS13CipherState(keySet: TLS13KeySchedule.keySet(trafficSecret: handshakeSecrets.server))

        let certificatePrivateKey = try P256.Signing.PrivateKey(derRepresentation: PEMDecoder.decode(self.tlsConfiguration.privateKeyPEM))
        let certificateDERChain = try PEMDecoder.decodeCertificates(self.tlsConfiguration.certificatePEM)

        let encryptedExtensions = TLS13HandshakeMessage.encryptedExtensions()
        try self.sendEncryptedHandshake(encryptedExtensions, using: &serverHandshakeCipher)
        transcript.append(encryptedExtensions)

        let certificate = TLS13HandshakeMessage.certificate(derCertificates: certificateDERChain)
        try self.sendEncryptedHandshake(certificate, using: &serverHandshakeCipher)
        transcript.append(certificate)

        let certificateVerify = try TLS13HandshakeMessage.certificateVerify(
            privateKey: certificatePrivateKey,
            transcriptHash: TLS13KeySchedule.transcriptHash(transcript)
        )
        try self.sendEncryptedHandshake(certificateVerify, using: &serverHandshakeCipher)
        transcript.append(certificateVerify)

        let serverFinished = TLS13HandshakeMessage.finished(
            verifyData: TLS13KeySchedule.finishedVerifyData(
                trafficSecret: handshakeSecrets.server,
                transcriptHash: TLS13KeySchedule.transcriptHash(transcript)
            )
        )
        try self.sendEncryptedHandshake(serverFinished, using: &serverHandshakeCipher)
        transcript.append(serverFinished)

        let applicationSecrets = TLS13KeySchedule.applicationTrafficSecrets(
            handshakeSecret: handshakeSecrets.handshakeSecret,
            transcriptHash: TLS13KeySchedule.transcriptHash(transcript)
        )

        let clientFinished = try readEncryptedHandshake(using: &clientHandshakeCipher)
        try self.verifyClientFinished(clientFinished, trafficSecret: handshakeSecrets.client, transcript: transcript)
        transcript.append(clientFinished)

        self.readCipher = TLS13CipherState(keySet: TLS13KeySchedule.keySet(trafficSecret: applicationSecrets.client))
        self.writeCipher = TLS13CipherState(keySet: TLS13KeySchedule.keySet(trafficSecret: applicationSecrets.server))
    }

    private func validate(_ clientHello: ClientHello) throws {
        guard try clientHello.supportedVersions.contains(.v1_3) else {
            throw TLS13Error.missingExtension(.supportedVersions)
        }
        guard clientHello.supportedCiphers.contains(.TLS_AES_128_GCM_SHA256) else {
            throw TLS13Error.unsupportedCipherSuite
        }
        _ = try self.selectClientKeyShare(from: clientHello)
        guard try clientHello.signatureAlgorithms.contains(TLS13HandshakeMessage.ecdsaSecp256r1Sha256) else {
            throw TLS13Error.unsupportedSignatureScheme
        }
    }

    private func selectClientKeyShare(from clientHello: ClientHello) throws -> ClientKeyShare {
        let clientKeyShares = try clientHello.clientKeys
        let clientSupportedGroups = try clientHello.supportedGroups
        let supportedGroups = KeyNamedGroup.supportedKeyShareGroups.filter { group in
            clientSupportedGroups.isEmpty || clientSupportedGroups.contains(group)
        }

        return try supportedGroups
            .compactMap { supportedGroup in
                clientKeyShares.first { $0.namedGroup == supportedGroup }
            }
            .first
            .orThrow(TLS13Error.unsupportedKeyShare)
    }

    private func sendEncryptedHandshake(_ handshakeMessage: Data, using cipher: inout TLS13CipherState) throws {
        let record = try cipher.seal(handshakeMessage, contentType: .handshake)
        try self.socket.writeData(record.data)
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
        while self.plaintextBuffer.isEmpty {
            try self.readApplicationData()
        }
        return self.plaintextBuffer.consume(bytes: 1).first!
    }

    public func readLine() throws -> String {
        var characters = ""
        var byte: UInt8 = 0
        repeat {
            byte = try self.read()
            if byte > 13 {
                characters.append(Character(UnicodeScalar(byte)))
            }
        } while byte != 10
        return characters
    }

    public func read(length: Int) throws -> [UInt8] {
        while self.plaintextBuffer.count < length {
            try self.readApplicationData()
        }
        return Array(self.plaintextBuffer.consume(bytes: length))
    }

    private func readApplicationData() throws {
        guard var cipher = readCipher else {
            throw TLS13Error.handshakeNotComplete
        }
        let record = try readTLSRecordSkippingCompatibilityRecords()
        let opened = try cipher.open(record)
        self.readCipher = cipher
        switch opened.contentType {
        case .applicationData:
            self.plaintextBuffer.append(opened.plaintext)
        case .alert:
            self.close()
            throw TLS13Error.invalidEncryptedRecord
        default:
            break
        }
    }

    public func writeUTF8(_ string: String) throws {
        try self.writeData(Data(string.utf8))
    }

    public func writeUInt8(_ data: [UInt8]) throws {
        try self.writeData(Data(data))
    }

    public func writeUInt8(_ data: ArraySlice<UInt8>) throws {
        try self.writeData(Data(data))
    }

    public func writeData(_ data: Data) throws {
        guard var cipher = writeCipher else {
            throw TLS13Error.handshakeNotComplete
        }
        var offset = 0
        while offset < data.count {
            let chunkEnd = min(offset + 16_384, data.count)
            let record = try cipher.seal(data[offset..<chunkEnd], contentType: .applicationData)
            try self.socket.writeData(record.data)
            offset = chunkEnd
        }
        self.writeCipher = cipher
    }

    public func writeData(_ data: NSData) throws {
        try self.writeData(data as Data)
    }

    public func writeFile(_ file: String.File) throws {
        var buffer = [UInt8](repeating: 0, count: 16_384)
        while true {
            let count = try file.read(&buffer)
            if count == 0 {
                return
            }
            try self.writeUInt8(buffer.prefix(count))
        }
    }

    public func close() {
        self.socket.close()
    }

    public var peerIP: String? {
        self.socket.peerIP
    }
}
