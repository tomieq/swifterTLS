import Swifter
import SwiftExtensions
import Foundation
import Crypto

enum ServerError: Error {
    case internalServerError
}
public class TLSSocket: SecureSocket {
    private let socket: Socket
    
    var buffer = Data()
    
    public var raw: Socket {
        socket
    }

    public required init(_ socket: Socket) {
        print("New socket")
        self.socket = socket
        
        do {
            let clientHello = try ClientHello(socket)
            print("Supported cipher suites: \(clientHello.supportedCiphers.map { $0.asString })")
            print("Keys: \(try clientHello.clientKeys.map{ $0.namedGroup.asString })")
            print("names: \(try clientHello.serverNames.map { $0.serverName })")
            print("supported groups: \(try clientHello.supportedGroups.map { $0.asString })")
            print("client keys: \(try clientHello.clientKeys.map { "\($0.namedGroup.asString) \($0.key)" })")
            
            // x25519 has 32 bytes of public key

            
            let supportedVersionExtension = TLSExtension(type: ExtensionName.supportedVersions.data,
                                                         body: TLSVersion.v1_3.data)
            let serverPrivateKey = Curve25519.KeyAgreement.PrivateKey()
            let serverPublicKey = serverPrivateKey.publicKey
            let serverPublicKeyData = serverPrivateKey.publicKey.rawRepresentation  // 32 bajty
            
            
            let keyShareExtension = TLSExtension(type: ExtensionName.keyShare.data,
                                                 body: KeyNamedGroup.x25519.data
                .appending(asTwoBytes: serverPublicKeyData.count)
                .appending(serverPublicKeyData))
            
            let clientPublicKeyData = try clientHello.clientKeys
                .filter { $0.namedGroup == .x25519 }
                .map { $0.key }.first
                .orThrow(ServerError.internalServerError)
            
           
            /*
*/
//            let earlySecret = HKDF<SHA256>.extract(
//                inputKeyMaterial: SymmetricKey(data: Data()),
//                salt: zeroSalt
//            )
//            
//            sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self,
//                                                 salt: earlySecret,
//                                                 sharedInfo: Data(),
//                                                 outputByteCount: 32)
//            let material = sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self,
//                                                                salt: SymmetricKey(data: earlySecret.withUnsafeBytes { Data($0) }),
//                                                                sharedInfo: Data(),
//                                                                outputByteCount: 32)
//            let handshakeSecret = HKDF<SHA256>.extract(inputKeyMaterial: material,
//                                    salt: SymmetricKey(data: earlySecret.withUnsafeBytes { Data($0) }))
            
            let serverHello = ServerHello(recordVersion: clientHello.record.version,
                                          serverHelloVersion: .v1_2,
                                          random: Data.random(length: 32),
                                          sessionID: clientHello.sessionID,
                                          chosenCipher: .TLS_AES_128_GCM_SHA256,
                                          compressionMethod: .null,
                                          extensions: [supportedVersionExtension, keyShareExtension])
            let serverHelloData = serverHello.data
            try socket.writeData(serverHelloData)
            
            let transcriptHash: SHA256.Digest = SHA256.hash(data: buffer + serverHelloData)
            let transcriptData = Data(transcriptHash)

            let clientPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: clientPublicKeyData)
            // Wspólny sekret (ECDHE)
            let sharedSecret = try serverPrivateKey.sharedSecretFromKeyAgreement(with: clientPublicKey)
            let sharedSecretData = sharedSecret.withUnsafeBytes { Data($0) } // 32 bytes
            
            func hkdfExpandLabel(secret: SymmetricKey, label: String, context: Data, length: Int) -> SymmetricKey {
                let fullLabel = "tls13 \(label)"
                var hkdfLabel = Data()
                hkdfLabel.append(asTwoBytes: length)
                hkdfLabel.append(asOneByte: fullLabel.count)
                hkdfLabel.append(contentsOf: fullLabel.utf8)
                hkdfLabel.append(asOneByte: context.count)
                hkdfLabel.append(context)

                return HKDF<SHA256>.expand(pseudoRandomKey: secret, info: hkdfLabel, outputByteCount: length)
            }
            
            /// GROK
            // TLS 1.3 key derivation
            // 32 bajty zer – długość SHA256
            let zeroSalt = Data(repeating: 0, count: 32)
            let earlySecret = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(size: .bits256), salt: zeroSalt)
            let derivedSecret = hkdfExpandLabel(
                secret: SymmetricKey(data: earlySecret),
                label: "derived",
                context: Data(), // Empty context for derived secret
                length: 32
            )
            let handshakeSecret = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: sharedSecret),
                                                       salt: derivedSecret.data)
            
            // Derive client and server handshake traffic secrets
            let serverHandshakeTrafficSecret = hkdfExpandLabel(
                secret: SymmetricKey(data: handshakeSecret),
                label: "s hs traffic",
                context: Data(transcriptHash),
                length: 32
            )
//            let clientHandshakeTrafficSecret = HKDF<SHA256>.expand(
//                pseudoRandomKey: handshakeSecret,
//                info: Data("c hs traffic".utf8) + transcriptHash,
//                outputByteCount: 32
//            )
            // Derive handshake keys and IVs
//            let clientWriteKey = HKDF<SHA256>.expand(
//                pseudoRandomKey: clientHandshakeTrafficSecret,
//                info: Data("key".utf8),
//                outputByteCount: 16 // AES-128-GCM uses 16-byte key
//            )
            let serverWriteKey = hkdfExpandLabel(
                secret: serverHandshakeTrafficSecret,
                label: "key",
                context: Data(), // Empty context for key and IV
                length: 16 // AES-128-GCM key
            )
//            let clientWriteIV = HKDF<SHA256>.expand(
//                pseudoRandomKey: clientHandshakeTrafficSecret,
//                info: Data("iv".utf8),
//                outputByteCount: 12 // AES-GCM uses 12-byte IV
//            )
            let serverWriteIV = hkdfExpandLabel(
                secret: serverHandshakeTrafficSecret,
                label: "iv",
                context: Data(),
                length: 12 // AES-GCM IV
            )
            
            var encryptedExtensions: [UInt8] = [
                0x08, // Handshake type: EncryptedExtensions
                0x00, 0x00, 0x02, // Length (example: 2 bytes for empty extensions)
                0x00, 0x00 // Empty extensions list
            ]

            print("serverWriteIV: \(serverWriteIV.data)")
            let sequenceNumber: UInt64 = 0
            // Encrypt the message using AES-128-GCM
            let serverKey = SymmetricKey(data: serverWriteKey)
            let sequenceBytes = withUnsafeBytes(of: sequenceNumber.bigEndian) { Data($0) }.suffix(12)
            print("sequenceBytes: \(sequenceBytes.count)")
            let nonceBytes = serverWriteIV.data.enumerated().map { index, byte in byte ^ sequenceBytes[index] }
            let nonce = try AES.GCM.Nonce(data: nonceBytes)
            let sealedBox = try AES.GCM.seal(
                Data(encryptedExtensions),
                using: serverKey,
                nonce: nonce,
                authenticating: Data() // Additional authenticated data, if needed
            )

            // Format as TLS record
            let record: [UInt8] = [
                0x17, // Content type: Application Data (encrypted handshake messages)
                0x03, 0x03, // Protocol version: TLS 1.2 (for compatibility)
            ] + UInt16(sealedBox.ciphertext.count + sealedBox.tag.count).data + sealedBox.ciphertext + sealedBox.tag
            /// CHATGPT
            // TLS 1.3: early secret = HKDF-Extract(zeros, "")
//            let earlySecret: HashedAuthenticationCode<SHA256> = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: Data()),
//                                                   salt: zeroSalt)
            
            
//            let symmetricKey: SymmetricKey = sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self,
//                                                                      salt: zeroSalt,
//                                                                      sharedInfo: Data(),
//                                                                      outputByteCount: 32)
//            let handshakeSecret: HashedAuthenticationCode<SHA256> = HKDF<SHA256>.extract(inputKeyMaterial: symmetricKey,
//                                                       salt: Data(earlySecret))
            

            /*
            func hkdfExpandLabel(secret: SymmetricKey, label: String, context: Data, length: Int) -> SymmetricKey {
                let fullLabel = "tls13 \(label)"
                var hkdfLabel = Data()
                hkdfLabel.append(asTwoBytes: length)
                hkdfLabel.append(asOneByte: fullLabel.count)
                hkdfLabel.append(contentsOf: fullLabel.utf8)
                hkdfLabel.append(asOneByte: context.count)
                hkdfLabel.append(context)

                return HKDF<SHA256>.expand(pseudoRandomKey: secret, info: hkdfLabel, outputByteCount: length)
            }
            
            let serverHandshakeTrafficSecret: SymmetricKey = hkdfExpandLabel(secret: SymmetricKey(data: handshakeSecret),
                                                               label: "s hs traffic",
                                                               context: transcriptData,
                                                               length: 32)
            print("traffic secret: \(serverHandshakeTrafficSecret.data.hexString)")
            let key: SymmetricKey = hkdfExpandLabel(secret: serverHandshakeTrafficSecret, label: "key", context: Data(), length: 16)
            let iv: SymmetricKey  = hkdfExpandLabel(secret: serverHandshakeTrafficSecret, label: "iv", context: Data(), length: 12)
            
            func buildNonce(iv: Data, sequenceNumber: UInt64) -> Data {
                var seq = withUnsafeBytes(of: sequenceNumber.bigEndian) { Data($0) }
                while seq.count < iv.count {
                    seq.insert(0, at: 0)
                }
                return Data(zip(iv, seq).map { $0 ^ $1 })
            }
            
            // SEND EcryptedExtensions
            
            let extensions = TLSExtension(type: ExtensionName.supportedVersions.data, body: TLSVersion.v1_3.data)
            let encryptedExtensions = EncryptedExtensions(extensions: [extensions])
            
            let out = encryptedExtensions.data(encrypt: { data in
                let nonce = buildNonce(iv: iv.data, sequenceNumber: 0)
                let sealedBox = try! AES.GCM.seal(data, using: key, nonce: AES.GCM.Nonce(data: nonce))
                return sealedBox.combined!
            })
             */
            try socket.writeData(record.data)
            
//            socket.close()
//            let record = try Record(socket: socket)
            print("record: \(record)")
            
        } catch {
            print("Error \(error)")
        }
    }
    
    public func read() throws -> UInt8 {
        let byte = try socket.read()
        buffer.append(byte)
        return byte
    }
    
    public func readLine() throws -> String {
//        fatalError()
        try socket.readLine()
    }
    
    public func read(length: Int) throws -> [UInt8] {
        let bytes = try socket.read(length: length)
        buffer.append(contentsOf: bytes)
        return bytes
    }
    
    public func writeUTF8(_ string: String) throws {
        try socket.writeUTF8(string)
    }
    
    public func writeUInt8(_ data: [UInt8]) throws {
        try socket.writeUInt8(data)
    }
    
    public func writeUInt8(_ data: ArraySlice<UInt8>) throws {
        try socket.writeUInt8(data)
    }
    
    public func writeData(_ data: Data) throws {
        try socket.writeData(data)
    }
    
    public func writeData(_ data: NSData) throws {
        try socket.writeData(data)
    }
    
    public func writeFile(_ file: String.File) throws {
        try socket.writeFile(file)
    }
    
    public func close() {
        socket.close()
    }
    
    public var peerIP: String? {
        "dummy"//socket.peerIP
    }
}


extension SymmetricKey {
    var data: Data {
        return withUnsafeBytes { Data($0) }
    }
}


/*
 
 
 Piszę w języku Swift serwer WWW obsługujący TLS. Do tej pory udało mi się otrzymać i zdekodować ClientHello oraz wysłać ServerHello. Powiedz mi jaki jest następny krok i jak to zaimplementować uywając biblioteki https://github.com/apple/swift-crypto.
 Dodam, że serwer powinien obsługiwać tylko TLS 1.3. W ServerHello odesłałem cipher TLS_AES_128_GCM_SHA256. Posiadam certyfikat X509 servera self-signed w formie zmiennej let cert: Data, który jest w formacie der.
 */
