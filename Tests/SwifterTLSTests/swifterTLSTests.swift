import Crypto
import Foundation
import Testing
@testable import SwifterTLS

private let testTLSConfiguration = TLSConfiguration(
    privateKeyPEM: """
    -----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgLxHL+J4cg1R+mnqM
    7SwS0x5Fr1FyDGTSGgQAezqPDXShRANCAAR6mbe54Kpb1haP7CIk7VlCssnCxLAG
    SfSUEm5MtQpA7BrbnPH7aOwlj89yTmhb+TN1a0eEjgK4WKmD0xb36DP5
    -----END PRIVATE KEY-----
    """,
    certificatePEM: """
    -----BEGIN CERTIFICATE-----
    MIIBmTCCAUSgAwIBAgIJAPg5p4jWM8buMAoGCCqGSM49BAMCMBUxEzARBgNVBAMT
    ClJvb3QgQ0EgUjEwHhcNMjUwNDE0MTA0NDAwWhcNMzUwNDE0MTA0NDAwWjAUMRIw
    EAYDVQQDEwlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR6mbe5
    4Kpb1haP7CIk7VlCssnCxLAGSfSUEm5MtQpA7BrbnPH7aOwlj89yTmhb+TN1a0eE
    jgK4WKmD0xb36DP5o34wfDAdBgNVHQ4EFgQUEhISEhISEhISEhISEhISEhISEhIw
    FAYDVR0RBA0wC4IJbG9jYWxob3N0MEUGA1UdIwQ+MDyAFIeHh4eHh4eHh4eHh4eH
    h4eHh4eHoRmkFzAVMRMwEQYDVQQDEwpSb290IENBIFIxggkA+DmniNYzxrswCgYI
    KoZIzj0EAwIDQwAwQMe3u4wV3csV3sGnbHWynADE50wasRxt67IFWOeg8ti3lW3e
    PBf7zUviqqGzo/BI28g6eFgA2sPsVlUBkkqm24E=
    -----END CERTIFICATE-----
    -----BEGIN CERTIFICATE-----
    MIIBUDCB/KADAgECAgkA+DmniNYzxrswCgYIKoZIzj0EAwIwFTETMBEGA1UEAxMK
    Um9vdCBDQSBSMTAeFw0yNTA0MTQxMDQ0MDBaFw0zNTA0MTQxMDQ0MDBaMBUxEzAR
    BgNVBAMTClJvb3QgQ0EgUjEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASyW8Ar
    hmuq67J7MyQHqBsX6eZW5/nFC1xvCfS0uQzcvT+7m2w8+1vgPnOs+fkSorQrnqAE
    2622pRv4bMCHjb55ozUwMzASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSH
    h4eHh4eHh4eHh4eHh4eHh4eHhzAKBggqhkjOPQQDAgNDADBAktauq8jL/mSgEzyh
    borIV2ZZzCL8726L94NseafSyx2qHYjJYYU0v7oub810/ENFmkn7XGh3d7zhB+jN
    C63WVg==
    -----END CERTIFICATE-----
    """
)

@Test func pemDecoderReadsConfiguredCertificateAndPrivateKey() throws {
    let certificates = try PEMDecoder.decodeCertificates(testTLSConfiguration.certificatePEM)
    let privateKey = try PEMDecoder.decode(testTLSConfiguration.privateKeyPEM)

    #expect(certificates.count == 2)
    #expect(certificates.allSatisfy { $0.first == 0x30 })
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
    let certificates = try PEMDecoder.decodeCertificates(testTLSConfiguration.certificatePEM)
    var message = TLS13HandshakeMessage.certificate(derCertificates: certificates)
    let entriesLength = certificates.reduce(0) { $0 + $1.count + 5 }

    #expect(message.consume(bytes: 1) == HandshakeType.certificate.rawValue.data)
    #expect(try message.consume(bytes: 3).int == message.count)
    #expect(try message.consume(bytes: 1).int == 0)
    #expect(try message.consume(bytes: 3).int == entriesLength)

    for certificate in certificates {
        #expect(try message.consume(bytes: 3).int == certificate.count)
        #expect(message.consume(bytes: certificate.count) == certificate)
        #expect(try message.consume(bytes: 2).int == 0)
    }
}
