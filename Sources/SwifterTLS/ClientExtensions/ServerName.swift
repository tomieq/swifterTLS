//
//  ServerName.swift
//  SwifterTLS
//
//  Created by Tomasz Kucharski on 10/07/2025.
//
import SwiftExtensions

struct ServerName {
    let nameType: ServerNameType
    let serverName: String
}

enum ServerNameType: UInt16 {
    case hostname = 0
}

extension ClientHello {
    var serverNames: [ServerName] {
        get throws {
            try extensions.filter { $0.name == .serverName }
                .flatMap {
                    var body = $0.body
                    var names: [ServerName] = []
                    let bodyLenght = try body.consume(bytes: 2).uInt16
                    guard bodyLenght > 3 else {
                        return names
                    }
                    while body.isEmpty.not {
                        // 2 bytes - name type
                        // 1 byte - name length
                        // n bytes - name
                        let nameType = ServerNameType(data: body.consume(bytes: 2))
                        let nameSize = try body.consume(bytes: 1).uInt8
                        let name = String(data: body.consume(bytes: Int(nameSize)), encoding: .utf8)
                        if let nameType, let name {
                            names.append(ServerName(nameType: nameType, serverName: name))
                        }
                    }
                    return names
                }
        }
    }
}
