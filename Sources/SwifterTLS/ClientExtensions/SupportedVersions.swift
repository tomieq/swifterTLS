extension ClientHello {
    var supportedVersions: [TLSVersion] {
        get throws {
            try extensions.filter { $0.name == .supportedVersions }
                .flatMap {
                    var body = $0.body
                    var versions: [TLSVersion] = []
                    let bodyLength = try body.consume(bytes: 1).uInt8
                    guard bodyLength == body.count else {
                        return versions
                    }
                    while body.isEmpty.not {
                        if let version = TLSVersion(data: body.consume(bytes: 2)) {
                            versions.append(version)
                        }
                    }
                    return versions
                }
        }
    }
}
