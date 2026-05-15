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
    case expectedClientHello
    case invalidBodyLength
    case unknownVersion
}

class ClientHello {
    let record: Record
    let handshakeData: Data
    let clientHelloVersion: TLSVersion
    let random: Data
    let sessionID: Data
    let supportedCiphers: [CipherSuite]
    let compressionMethods: [CompressionMethod]
    let extensions: [TLSExtension]
    
    init(_ socket: Socket) throws {
        record = try Record(socket: socket, maxLength: .KB(5))
        handshakeData = record.body
        var body = record.body
        // make sure it is handshake message
        guard record.recordType == .handshake else {
            throw ClientHelloError.expectedHandshakeMessage
        }
        // make sure it is client hello
        guard body.consume(bytes: 1) == HandshakeType.clientHello else {
            throw ClientHelloError.expectedClientHello
        }
        // make sure length matches the body count
        guard try body.consume(bytes: 3).int == body.count else {
            throw ClientHelloError.invalidBodyLength
        }
        clientHelloVersion = try TLSVersion(data: body.consume(bytes: 2))
            .orThrow(ClientHelloError.unknownVersion)
        random = body.consume(bytes: 32)
        sessionID = body.consume(bytes: try body.consume(bytes: 1).int)
        // supported ciphers
        var cipherData = body.consume(bytes: try body.consume(bytes: 2).int)
        var ciphers: [CipherSuite] = []
        while cipherData.isEmpty.not {
            CipherSuite(data: cipherData.consume(bytes: 2))
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
        var extensions: [TLSExtension] = []
        while extensionsData.isEmpty.not {
            TLSExtension(type: extensionsData.consume(bytes: 2),
                         body: extensionsData.consume(bytes: try extensionsData.consume(bytes: 2).int))
            .convert {
                extensions.append($0)
            }
        }
        self.extensions = extensions
    }
}


