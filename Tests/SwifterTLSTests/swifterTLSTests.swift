import Crypto
import Foundation
import Testing
@testable import SwifterTLS

private let testTLSConfiguration = TLSConfiguration(
    privateKeyPEM: """
    -----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu7aVzRrFZBOsyrVq
    MBf2rsugV1K+LS5cqZebitNTINmhRANCAASlaggH66TIi2BqrV3iKbM8FveSbTAM
    wj0bp8hMELrBSF4B+H645KFVjhMrsf3pf6wJ0dEVo/BrLKYDUtfTdsZb
    -----END PRIVATE KEY-----
    """,
    certificatePEM: """
    -----BEGIN CERTIFICATE-----
    MIIBUDCB/KADAgECAgkA+DmniNYzxrswCgYIKoZIzj0EAwIwFDESMBAGA1UEAxMJ
    bG9jYWxob3N0MB4XDTI1MDQxNDEwNDQwMFoXDTM1MDQxNDEwNDQwMFowFDESMBAG
    A1UEAxMJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpWoIB+uk
    yItgaq1d4imzPBb3km0wDMI9G6fITBC6wUheAfh+uOShVY4TK7H96X+sCdHRFaPw
    ayymA1LX03bGW6M3MDUwHQYDVR0OBBYEFIeHh4eHh4eHh4eHh4eHh4eHh4eHMBQG
    A1UdEQQNMAuCCWxvY2FsaG9zdDAKBggqhkjOPQQDAgNDADBAHBAK3Mgmt38pO7Sq
    iXdOjeW0OqTr6HBgxvBicJcxQ4UeUcCe0LHUvjLhNoWzejc6Av9CzyXcXedZcBH9
    86YpNA==
    -----END CERTIFICATE-----
    """
)

@Test func pemDecoderReadsConfiguredCertificateAndPrivateKey() throws {
    let certificate = try PEMDecoder.decode(testTLSConfiguration.certificatePEM)
    let privateKey = try PEMDecoder.decode(testTLSConfiguration.privateKeyPEM)

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
    let certificate = try PEMDecoder.decode(testTLSConfiguration.certificatePEM)
    var message = TLS13HandshakeMessage.certificate(derCertificate: certificate)

    #expect(message.consume(bytes: 1) == HandshakeType.certificate.rawValue.data)
    #expect(try message.consume(bytes: 3).int == message.count)
    #expect(try message.consume(bytes: 1).int == 0)
    #expect(try message.consume(bytes: 3).int == certificate.count + 5)
    #expect(try message.consume(bytes: 3).int == certificate.count)
    #expect(message.consume(bytes: certificate.count) == certificate)
    #expect(try message.consume(bytes: 2).int == 0)
}
