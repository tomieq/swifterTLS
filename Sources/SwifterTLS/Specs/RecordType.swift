//
//  RecordType.swift
//  SwifterTLS
//
//  Created by Tomasz Kucharski on 10/07/2025.
//

enum RecordType: UInt8 {
    case changeCipherSpec = 0x14
    case alert = 0x15
    case handshake = 0x16
    case applicationData = 0x17
}
