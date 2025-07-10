//
//  CipherSuite.swift
//  SwifterTLS
//
//  Created by Tomasz Kucharski on 09/07/2025.
//

enum CipherSuite: UInt16, CaseIterable {
    case TLS_AES_128_GCM_SHA256         = 0x1301
    case TLS_AES_256_GCM_SHA384         = 0x1302
    case TLS_CHACHA20_POLY1305_SHA256   = 0x1303
    case TLS_AES_128_CCM_SHA256         = 0x1304
    case TLS_AES_128_CCM_8_SHA256       = 0x1305
}

extension CipherSuite {
    var asString: String {
        "\(self)".components(separatedBy: ".").last ?? "\(self)"
    }
}
