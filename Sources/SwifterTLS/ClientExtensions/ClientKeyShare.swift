//
//  ClientKeyShare.swift
//  SwifterTLS
//
//  Created by Tomasz Kucharski on 10/07/2025.
//
import Foundation
import SwiftExtensions

struct ClientKeyShare {
    let namedGroup: KeyNamedGroup
    let key: Data
}

enum ClientKeyShareError: Error {
    case invalidKeyShareBodyLength
}
extension ClientHello {
    var clientKeys: [ClientKeyShare] {
        get throws {
            try extensions.filter { $0.name == .keyShare }
                .flatMap {
                    var keys: [ClientKeyShare] = []
                    var body = $0.body
                    let length = try body.consume(bytes: 2).uInt16
                    guard length > 3, length == body.count else {
                        throw ClientKeyShareError.invalidKeyShareBodyLength
                    }
                    while body.isEmpty.not {
                        // 2 bytes - named group
                        // 2 bytes - key length
                        // n bytes - key
                        let namedGroup = KeyNamedGroup(data: body.consume(bytes: 2))
                        let key = try body.consume(bytes: body.consume(bytes: 2).int)
                        if let namedGroup {
                            keys.append(ClientKeyShare(namedGroup: namedGroup, key: key))
                        }
                    }
                    return keys
                }
        }
    }
}
