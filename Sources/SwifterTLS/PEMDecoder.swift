//
//  PEMDecoder.swift
//  SwifterTLS
// 
//  Created by: tomieq on 16/05/2026
//
import Foundation

enum PEMDecoder {
    static func decode(_ pem: String) throws -> Data {
        let blocks = try decodeAll(pem)
        guard blocks.count == 1, let data = blocks.first else {
            throw TLS13Error.invalidPEM
        }
        return data
    }

    static func decodeCertificates(_ pem: String) throws -> [Data] {
        let blocks = try decodeAll(pem)
        guard !blocks.isEmpty else {
            throw TLS13Error.invalidPEM
        }
        return blocks
    }

    private static func decodeAll(_ pem: String) throws -> [Data] {
        var blocks: [Data] = []
        var base64Lines: [String] = []

        for line in pem.split(separator: "\n", omittingEmptySubsequences: false) {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.hasPrefix("-----BEGIN ") {
                base64Lines.removeAll(keepingCapacity: true)
            } else if trimmed.hasPrefix("-----END ") {
                guard let data = Data(base64Encoded: base64Lines.joined()) else {
                    throw TLS13Error.invalidPEM
                }
                blocks.append(data)
                base64Lines.removeAll(keepingCapacity: true)
            } else if !trimmed.isEmpty {
                base64Lines.append(trimmed)
            }
        }

        guard base64Lines.isEmpty else {
            throw TLS13Error.invalidPEM
        }
        return blocks
    }

}
