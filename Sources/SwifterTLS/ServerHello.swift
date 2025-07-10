//
//  ServerHello.swift
//  SwifterTLS
//
//  Created by Tomasz Kucharski on 10/07/2025.
//

import Foundation
import Swifter
import SwiftExtensions

class ServerHello {
    let recordVersion: TLSVersion
    let serverHelloVersion: TLSVersion
    let random: Data
    let sessionID: Data
    let chosenCipher: CipherSuite
    let compressionMethod: CompressionMethod
    let extensions: [TLSExtension]

    
    init(recordVersion: TLSVersion,
         serverHelloVersion: TLSVersion,
         random: Data,
         sessionID: Data,
         chosenCipher: CipherSuite,
         compressionMethod: CompressionMethod,
         extensions: [TLSExtension]) {
        self.recordVersion = recordVersion
        self.serverHelloVersion = serverHelloVersion
        self.random = random
        self.sessionID = sessionID
        self.chosenCipher = chosenCipher
        self.compressionMethod = compressionMethod
        self.extensions = extensions
    }
}

extension ServerHello {
    var data: Data {
        var extensionsBody = Data()
        extensions.forEach {
            extensionsBody.append($0.data)
        }
        
        let message = serverHelloVersion.rawValue.data
            .appending(random)
            .appending(asOneByte: sessionID.count)
            .appending(sessionID)
            .appending(chosenCipher)
            .appending(compressionMethod)
            .appending(asTwoBytes: extensionsBody.count)
            .appending(extensionsBody)
        
        let body = HandshakeType.serverHello.rawValue.data
            .appending(asThreeBytes: message.count)
            .appending(message)
        return Record(recordType: .handshake, version: recordVersion, body: body).data
    }
}
