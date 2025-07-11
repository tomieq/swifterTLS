//
//  KeyNamedGroup.swift
//  SwifterTLS
//
//  Created by Tomasz Kucharski on 10/07/2025.
//

enum KeyNamedGroup: UInt16 {
    case secp256r1 = 0x17
    case secp384r1 = 0x18
    case secp521r1 = 0x19
    
    case x25519    = 0x1d
    case x448      = 0x1e
    
    case GC256C    = 0x24
    case curveSM2  = 0x29 // chineese key spec
    
    /* Finite Field Groups (DHE) */
    case ffdhe2048 = 0x0100
    case ffdhe3072 = 0x0101
    case ffdhe4096 = 0x0102
    case ffdhe6144 = 0x0103
    case ffdhe8192 = 0x0104
    
    case arbitrary_explicit_prime_curves = 0xFF01
    case arbitrary_explicit_char2_curves = 0xFF02
}

extension KeyNamedGroup {
    var isSupported: Bool {
        [.x25519].contains(self)
    }
}

extension KeyNamedGroup {
    var asString: String {
        "\(self)".components(separatedBy: ".").last ?? "\(self)"
    }
}
