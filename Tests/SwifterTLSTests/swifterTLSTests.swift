import Crypto
import Foundation
import Testing
@testable import SwifterTLS

@Test func pemDecoderReadsConfiguredCertificateAndPrivateKey() throws {
    let certificate = try PEMDecoder.decode(Config.certificate)
    let privateKey = try PEMDecoder.decode(Config.privateKey)

    #expect(certificate.first == 0x30)
    #expect(privateKey.first == 0x30)
    #expect(throws: Never.self) {
        _ = try P256.Signing.PrivateKey(derRepresentation: privateKey)
    }
}

@Test func tls13CipherStateRoundTripsApplicationData() throws {
    let trafficSecret = SymmetricKey(data: Data(repeating: 7, count: 32))
    let keySet = TLS13KeySchedule.keySet(trafficSecret: trafficSecret)
    var writer = TLS13CipherState(keySet: keySet)
    var reader = TLS13CipherState(keySet: keySet)

    let record = try writer.seal(Data("GET / HTTP/1.1\r\n".utf8), contentType: .applicationData)
    let opened = try reader.open(record)

    #expect(opened.contentType == .applicationData)
    #expect(opened.plaintext == Data("GET / HTTP/1.1\r\n".utf8))
}

@Test func certificateMessageUsesTLS13VectorLayout() throws {
    let certificate = try PEMDecoder.decode(Config.certificate)
    var message = TLS13HandshakeMessage.certificate(derCertificate: certificate)

    #expect(message.consume(bytes: 1) == HandshakeType.certificate.rawValue.data)
    #expect(try message.consume(bytes: 3).int == message.count)
    #expect(try message.consume(bytes: 1).int == 0)
    #expect(try message.consume(bytes: 3).int == certificate.count + 5)
    #expect(try message.consume(bytes: 3).int == certificate.count)
    #expect(message.consume(bytes: certificate.count) == certificate)
    #expect(try message.consume(bytes: 2).int == 0)
}
