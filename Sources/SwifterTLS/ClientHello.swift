//
//  ClientHello.swift
//  SwifterTLS
//
//  Created by Tomasz Kucharski on 09/07/2025.
//
import Swifter
import SwiftExtensions
import Foundation

enum ClientHelloError: Error {
    case expectedHandshakeMessage
    case messageTooLong(DataSize)
    case expectedClientHello
    case invalidBodyLength
    case unknownVersion
}

class ClientHello {
    let recordVersion: UInt16
    let clientHelloVersion: TLSVersion
    let random: Data
    let sessionID: Data
    let supportedCiphers: [CipherSuite]
    let compressionMethods: [CompressionMethod]
    let extensions: [ClientExtension]
    
    init(_ socket: Socket) throws {
        // make sure it is handshake message
        guard try socket.read() == RecordType.handshake.rawValue else {
            throw ClientHelloError.expectedHandshakeMessage
        }
        recordVersion = try socket.read(length: 2).data.uInt16
        let length = try socket.read(length: 2).data.int
        guard DataSize(length) < .KB(5) else {
            throw ClientHelloError.messageTooLong(DataSize(length))
        }
        var body = try socket.read(length: length).data
        // make sure it is client hello
        guard try body.consume(bytes: 1).uInt8 == HandshakeType.clientHello.rawValue else {
            throw ClientHelloError.expectedClientHello
        }
        // make sure length matches the body count
        guard try body.consume(bytes: 3).int == body.count else {
            throw ClientHelloError.invalidBodyLength
        }
        clientHelloVersion = try TLSVersion(rawValue: try body.consume(bytes: 2).uInt16)
            .orThrow(ClientHelloError.unknownVersion)
        print(clientHelloVersion)
        random = body.consume(bytes: 32)
        sessionID = body.consume(bytes: try body.consume(bytes: 1).int)
        // supported ciphers
        var cipherData = body.consume(bytes: try body.consume(bytes: 2).int)
        var ciphers: [CipherSuite] = []
        while cipherData.isEmpty.not {
            CipherSuite(rawValue: try cipherData.consume(bytes: 2).uInt16)
                .onValue { cipher in
                    ciphers.append(cipher)
                }
        }
        supportedCiphers = ciphers
        // compression methods
        let compressionMethodsData = body.consume(bytes: try body.consume(bytes: 1).int)
        compressionMethods = compressionMethodsData.bytes.compactMap { CompressionMethod(rawValue: $0) }
        // extensions
        var extensionsData = body.consume(bytes: try body.consume(bytes: 2).int)
        var extensions: [ClientExtension] = []
        while extensionsData.isEmpty.not {
            ClientExtension(type: extensionsData.consume(bytes: 2),
                            body: extensionsData.consume(bytes: 2))
            .convert {
                extensions.append($0)
            }
        }
        self.extensions = extensions
    }
}
