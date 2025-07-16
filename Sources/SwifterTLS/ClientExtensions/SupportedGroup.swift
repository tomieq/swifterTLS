//
//  SupportedGroup.swift
//  SwifterTLS
//
//  Created by Tomasz Kucharski on 16/07/2025.
//

extension ClientHello {
    var supportedGroups: [KeyNamedGroup] {
        get throws {
            try extensions.filter { $0.name == .supportedGroups }
                .flatMap {
                    var body = $0.body
                    var groups: [KeyNamedGroup] = []
                    let bodyLenght = try body.consume(bytes: 2).uInt16
                    guard bodyLenght > 0 else {
                        return groups
                    }
                    while body.isEmpty.not {
                        if let group = KeyNamedGroup(data: body.consume(bytes: 2)) {
                            groups.append(group)
                        }
                    }
                    return groups
                }
        }
    }
}
