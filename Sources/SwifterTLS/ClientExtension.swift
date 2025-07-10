//
//  ClientExtension.swift
//  SwifterTLS
//
//  Created by Tomasz Kucharski on 09/07/2025.
//
import Foundation
import SwiftExtensions

struct ClientExtension {
    let type: Data
    let body: Data
    
    lazy var name: ExtensionName? = {
        Optional { try type.uInt16 }.map(ExtensionName.init).or(nil)
    }()
}

extension ClientExtension: Convertible {}
