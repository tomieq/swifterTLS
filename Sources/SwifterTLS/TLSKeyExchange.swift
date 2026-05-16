import Crypto
import Foundation

struct TLSKeyExchange {
    let namedGroup: KeyNamedGroup
    let publicKey: Data

    private let sharedSecretFromClientKey: (Data) throws -> SharedSecret

    func sharedSecret(with clientPublicKey: Data) throws -> SharedSecret {
        try self.sharedSecretFromClientKey(clientPublicKey)
    }
}

extension TLSKeyExchange {
    static func serverKeyShare(for namedGroup: KeyNamedGroup) throws -> TLSKeyExchange {
        switch namedGroup {
        case .x25519:
            let privateKey = Curve25519.KeyAgreement.PrivateKey()
            return TLSKeyExchange(
                namedGroup: namedGroup,
                publicKey: privateKey.publicKey.rawRepresentation,
                sharedSecretFromClientKey: { clientPublicKey in
                    let publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: clientPublicKey)
                    return try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
                }
            )
        case .secp256r1:
            let privateKey = P256.KeyAgreement.PrivateKey()
            return TLSKeyExchange(
                namedGroup: namedGroup,
                publicKey: privateKey.publicKey.x963Representation,
                sharedSecretFromClientKey: { clientPublicKey in
                    let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: clientPublicKey)
                    return try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
                }
            )
        case .secp384r1:
            let privateKey = P384.KeyAgreement.PrivateKey()
            return TLSKeyExchange(
                namedGroup: namedGroup,
                publicKey: privateKey.publicKey.x963Representation,
                sharedSecretFromClientKey: { clientPublicKey in
                    let publicKey = try P384.KeyAgreement.PublicKey(x963Representation: clientPublicKey)
                    return try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
                }
            )
        case .secp521r1:
            let privateKey = P521.KeyAgreement.PrivateKey()
            return TLSKeyExchange(
                namedGroup: namedGroup,
                publicKey: privateKey.publicKey.x963Representation,
                sharedSecretFromClientKey: { clientPublicKey in
                    let publicKey = try P521.KeyAgreement.PublicKey(x963Representation: clientPublicKey)
                    return try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
                }
            )
        default:
            throw TLS13Error.unsupportedKeyShare
        }
    }
}
