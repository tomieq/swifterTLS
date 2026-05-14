//
//  EncryptedExtensions.swift
//  SwifterTLS
//
//  Created by Tomasz Kucharski on 11/07/2025.
//

import Foundation
import Swifter
import SwiftExtensions

class EncryptedExtensions {
    let extensions: [TLSExtension]

    init(extensions: [TLSExtension]) {
        self.extensions = extensions
    }
}

extension EncryptedExtensions {
    func data(encrypt: (Data) -> Data) -> Data {
        var extensionsBody = Data()
        extensions.forEach {
            extensionsBody.append($0.data)
        }
        let message = Data()
            .appending(asTwoBytes: extensionsBody.count)
            .appending(extensionsBody)
        
        let body = HandshakeType.encryptedExtensions.rawValue.data
            .appending(asThreeBytes: message.count)
            .appending(message)
        return Record(recordType: .handshake, version: .v1_2, body: encrypt(body)).data
    }
}
