import Foundation

extension ClientHello {
    var signatureAlgorithms: [Data] {
        get throws {
            try extensions.filter { $0.name == .signatureAlgorithms }
                .flatMap {
                    var body = $0.body
                    var algorithms: [Data] = []
                    let bodyLength = try body.consume(bytes: 2).uInt16
                    guard bodyLength == body.count else {
                        return algorithms
                    }
                    while body.isEmpty.not {
                        algorithms.append(body.consume(bytes: 2))
                    }
                    return algorithms
                }
        }
    }
}
