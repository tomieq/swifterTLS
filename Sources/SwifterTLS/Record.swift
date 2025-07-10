//
//  Record.swift
//  SwifterTLS
//
//  Created by Tomasz Kucharski on 10/07/2025.
//

import Foundation
import Swifter
import SwiftExtensions

enum RecordError: Error {
    case invalidRecordType
    case invalidVersion
    case messageTooLong(DataSize)
}

class Record {
    let recordType: RecordType
    let version: TLSVersion
    var body: Data
    
    init (recordType: RecordType, version: TLSVersion, body: Data) {
        self.recordType = recordType
        self.version = version
        self.body = body
    }

    init(socket: Socket, maxLength: DataSize? = nil) throws {
        recordType = try RecordType(rawValue: socket.read()).orThrow(RecordError.invalidRecordType)
        version = try TLSVersion(data: try socket.read(length: 2).data).orThrow(RecordError.invalidVersion)
        let length = try socket.read(length: 2).data.int
        if let maxLength {
            guard DataSize(length) < maxLength else {
                throw RecordError.messageTooLong(DataSize(length))
            }
        }
        body = try socket.read(length: length).data
    }
}

extension Record: CustomStringConvertible {
    var description: String {
        "recordType: \(recordType), version: \(version)"
    }
}

extension Record {
    var data: Data {
        recordType.rawValue.data
            .appending(version)
            .appending(asTwoBytes: body.count)
            .appending(body)
    }
}
