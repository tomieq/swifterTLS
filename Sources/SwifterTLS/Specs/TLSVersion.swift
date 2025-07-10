//
//  TLSVersion.swift
//  SwifterTLS
//
//  Created by Tomasz Kucharski on 09/07/2025.
//

enum TLSVersion: UInt16 {
    case v1_0 = 0x0301
    case v1_1 = 0x0302
    case v1_2 = 0x0303
    case v1_3 = 0x0304
}

extension TLSVersion: CustomStringConvertible {
    var description: String {
        switch self {
        case .v1_0:
            "TLS 1.0"
        case .v1_1:
            "TLS 1.1"
        case .v1_2:
            "TLS 1.2"
        case .v1_3:
            "TLS 1.3"
        }
    }
}
