import Crypto
import Foundation
import SwiftExtensions

enum TLS13Error: Error {
    case missingConfiguration
    case missingExtension(ExtensionName)
    case unsupportedCipherSuite
    case unsupportedKeyShare
    case unsupportedSignatureScheme
    case invalidPEM
    case invalidEncryptedRecord
    case invalidInnerPlaintext
    case invalidFinished
    case handshakeNotComplete
}

enum TLS13ContentType: UInt8 {
    case changeCipherSpec = 0x14
    case alert = 0x15
    case handshake = 0x16
    case applicationData = 0x17
}

struct TLS13KeySet {
    let key: SymmetricKey
    let iv: Data
}

struct TLS13CipherState {
    private let keySet: TLS13KeySet
    private var sequenceNumber: UInt64 = 0

    init(keySet: TLS13KeySet) {
        self.keySet = keySet
    }

    mutating func seal(_ plaintext: Data, contentType: TLS13ContentType) throws -> Record {
        var innerPlaintext = plaintext
        innerPlaintext.append(contentType.rawValue)

        let encryptedLength = innerPlaintext.count + 16
        let header = RecordType.applicationData.data
            .appending(TLSVersion.v1_2)
            .appending(asTwoBytes: encryptedLength)
        let nonce = try AES.GCM.Nonce(data: nonceBytes())
        let sealedBox = try AES.GCM.seal(innerPlaintext, using: keySet.key, nonce: nonce, authenticating: header)
        sequenceNumber += 1
        return Record(recordType: .applicationData, version: .v1_2, body: sealedBox.ciphertext + sealedBox.tag)
    }

    mutating func open(_ record: Record) throws -> (contentType: TLS13ContentType, plaintext: Data) {
        guard record.recordType == .applicationData, record.body.count >= 17 else {
            throw TLS13Error.invalidEncryptedRecord
        }

        let header = Data([record.recordType.rawValue])
            .appending(record.version)
            .appending(asTwoBytes: record.body.count)
        let tagStart = record.body.index(record.body.endIndex, offsetBy: -16)
        let ciphertext = record.body[..<tagStart]
        let tag = record.body[tagStart...]
        let sealedBox = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonceBytes()), ciphertext: ciphertext, tag: tag)
        let innerPlaintext = try AES.GCM.open(sealedBox, using: keySet.key, authenticating: header)
        sequenceNumber += 1
        return try TLS13CipherState.parseInnerPlaintext(innerPlaintext)
    }

    private func nonceBytes() -> Data {
        var paddedSequence = Data(repeating: 0, count: keySet.iv.count - MemoryLayout<UInt64>.size)
        var bigEndianSequence = sequenceNumber.bigEndian
        paddedSequence.append(Data(bytes: &bigEndianSequence, count: MemoryLayout<UInt64>.size))
        return Data(zip(keySet.iv, paddedSequence).map { $0 ^ $1 })
    }

    private static func parseInnerPlaintext(_ data: Data) throws -> (contentType: TLS13ContentType, plaintext: Data) {
        var index = data.index(before: data.endIndex)
        while data[index] == 0 {
            guard index > data.startIndex else {
                throw TLS13Error.invalidInnerPlaintext
            }
            index = data.index(before: index)
        }
        guard let contentType = TLS13ContentType(rawValue: data[index]) else {
            throw TLS13Error.invalidInnerPlaintext
        }
        return (contentType, data[..<index])
    }
}

enum TLS13KeySchedule {
    static let hashLength = 32

    static func handshakeTrafficSecrets(sharedSecret: SharedSecret, transcriptHash: Data) -> (client: SymmetricKey, server: SymmetricKey, handshakeSecret: SymmetricKey) {
        let zero = Data(repeating: 0, count: hashLength)
        let earlySecret = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: zero), salt: zero)
        let derivedSecret = deriveSecret(secret: SymmetricKey(data: earlySecret), label: "derived", messages: Data())
        let handshakeSecret = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: sharedSecret), salt: derivedSecret.data)
        let clientSecret = hkdfExpandLabel(secret: SymmetricKey(data: handshakeSecret), label: "c hs traffic", context: transcriptHash, length: hashLength)
        let serverSecret = hkdfExpandLabel(secret: SymmetricKey(data: handshakeSecret), label: "s hs traffic", context: transcriptHash, length: hashLength)
        return (clientSecret, serverSecret, SymmetricKey(data: handshakeSecret))
    }

    static func applicationTrafficSecrets(handshakeSecret: SymmetricKey, transcriptHash: Data) -> (client: SymmetricKey, server: SymmetricKey) {
        let zero = Data(repeating: 0, count: hashLength)
        let derivedSecret = deriveSecret(secret: handshakeSecret, label: "derived", messages: Data())
        let masterSecret = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: zero), salt: derivedSecret.data)
        let clientSecret = hkdfExpandLabel(secret: SymmetricKey(data: masterSecret), label: "c ap traffic", context: transcriptHash, length: hashLength)
        let serverSecret = hkdfExpandLabel(secret: SymmetricKey(data: masterSecret), label: "s ap traffic", context: transcriptHash, length: hashLength)
        return (clientSecret, serverSecret)
    }

    static func keySet(trafficSecret: SymmetricKey) -> TLS13KeySet {
        TLS13KeySet(
            key: hkdfExpandLabel(secret: trafficSecret, label: "key", context: Data(), length: 16),
            iv: hkdfExpandLabel(secret: trafficSecret, label: "iv", context: Data(), length: 12).data
        )
    }

    static func finishedVerifyData(trafficSecret: SymmetricKey, transcriptHash: Data) -> Data {
        let finishedKey = hkdfExpandLabel(secret: trafficSecret, label: "finished", context: Data(), length: hashLength)
        return Data(HMAC<SHA256>.authenticationCode(for: transcriptHash, using: finishedKey))
    }

    static func transcriptHash(_ transcript: Data) -> Data {
        Data(SHA256.hash(data: transcript))
    }

    private static func deriveSecret(secret: SymmetricKey, label: String, messages: Data) -> SymmetricKey {
        hkdfExpandLabel(secret: secret, label: label, context: transcriptHash(messages), length: hashLength)
    }

    private static func hkdfExpandLabel(secret: SymmetricKey, label: String, context: Data, length: Int) -> SymmetricKey {
        let fullLabel = "tls13 " + label
        var hkdfLabel = Data()
        hkdfLabel.append(asTwoBytes: length)
        hkdfLabel.append(asOneByte: fullLabel.utf8.count)
        hkdfLabel.append(contentsOf: fullLabel.utf8)
        hkdfLabel.append(asOneByte: context.count)
        hkdfLabel.append(context)
        return HKDF<SHA256>.expand(pseudoRandomKey: secret, info: hkdfLabel, outputByteCount: length)
    }
}

enum TLS13HandshakeMessage {
    static let ecdsaSecp256r1Sha256 = Data([0x04, 0x03])

    static func encryptedExtensions(_ extensions: [TLSExtension] = []) -> Data {
        var extensionsBody = Data()
        extensions.forEach { extensionsBody.append($0.data) }
        let message = Data()
            .appending(asTwoBytes: extensionsBody.count)
            .appending(extensionsBody)
        return handshake(type: .encryptedExtensions, message: message)
    }

    static func certificate(derCertificate: Data) -> Data {
        let certificateEntry = Data()
            .appending(asThreeBytes: derCertificate.count)
            .appending(derCertificate)
            .appending(asTwoBytes: 0)
        let message = Data([0])
            .appending(asThreeBytes: certificateEntry.count)
            .appending(certificateEntry)
        return handshake(type: .certificate, message: message)
    }

    static func certificateVerify(privateKey: P256.Signing.PrivateKey, transcriptHash: Data) throws -> Data {
        let context = Data(repeating: 0x20, count: 64)
            + Data("TLS 1.3, server CertificateVerify".utf8)
            + Data([0])
            + transcriptHash
        let signature = try privateKey.signature(for: context).derRepresentation
        let message = ecdsaSecp256r1Sha256
            .appending(asTwoBytes: signature.count)
            .appending(signature)
        return handshake(type: .certificateVerify, message: message)
    }

    static func finished(verifyData: Data) -> Data {
        handshake(type: .finished, message: verifyData)
    }

    private static func handshake(type: HandshakeType, message: Data) -> Data {
        type.rawValue.data
            .appending(asThreeBytes: message.count)
            .appending(message)
    }
}

enum PEMDecoder {
    static func decode(_ pem: String) throws -> Data {
        let base64 = pem
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.hasPrefix("-----") && !$0.isEmpty }
            .joined()
        guard let data = Data(base64Encoded: base64) else {
            throw TLS13Error.invalidPEM
        }
        return data
    }
}

extension SymmetricKey {
    var data: Data {
        withUnsafeBytes { Data($0) }
    }
}
