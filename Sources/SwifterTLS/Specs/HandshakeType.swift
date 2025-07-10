//
//  HandshakeType.swift
//  SwifterTLS
//
//  Created by Tomasz Kucharski on 10/07/2025.
//

enum HandshakeType: UInt8 {
    // TLS common
    case helloRequest = 0x00
    case clientHello = 0x01
    case serverHello = 0x02
    case certificate = 0x0B
    case certificateRequest = 0x0D
    case certificateVerify = 0x0F
    case finished = 0x14
    
    // new in TLS 1.3
    case newSessionTicket = 4           // TLS 1.3
    case endOfEarlyData = 5             // TLS 1.3
    case helloRetryRequest = 6          // TLS 1.3
    case encryptedExtensions = 8        // TLS 1.3
    case keyUpdate = 24                 // TLS 1.3
    
    case messageHash = 254
}
