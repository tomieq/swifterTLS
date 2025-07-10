//
//  TLSExtension.swift
//  SwifterTLS
//
//  Created by Tomasz Kucharski on 09/07/2025.
//
import Foundation
import SwiftExtensions

class TLSExtension {
    let type: Data
    let body: Data
    
    init(type: Data, body: Data) {
        self.type = type
        self.body = body
    }

    lazy var name: ExtensionName? = {
        Optional { try type.uInt16 }.map(ExtensionName.init).or(nil)
    }()
}

extension TLSExtension: Convertible {}

extension TLSExtension {
    var data: Data {
        type.appending(asTwoBytes: body.count).appending(body)
    }
}
