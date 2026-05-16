import Foundation
import Swifter
import SwifterTLS

private let tlsConfiguration = TLSConfiguration(
    privateKeyPEM: """
    -----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu7aVzRrFZBOsyrVq
    MBf2rsugV1K+LS5cqZebitNTINmhRANCAASlaggH66TIi2BqrV3iKbM8FveSbTAM
    wj0bp8hMELrBSF4B+H645KFVjhMrsf3pf6wJ0dEVo/BrLKYDUtfTdsZb
    -----END PRIVATE KEY-----
    """,
    certificatePEM: """
    -----BEGIN CERTIFICATE-----
    MIIBUDCB/KADAgECAgkA+DmniNYzxrswCgYIKoZIzj0EAwIwFDESMBAGA1UEAxMJ
    bG9jYWxob3N0MB4XDTI1MDQxNDEwNDQwMFoXDTM1MDQxNDEwNDQwMFowFDESMBAG
    A1UEAxMJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpWoIB+uk
    yItgaq1d4imzPBb3km0wDMI9G6fITBC6wUheAfh+uOShVY4TK7H96X+sCdHRFaPw
    ayymA1LX03bGW6M3MDUwHQYDVR0OBBYEFIeHh4eHh4eHh4eHh4eHh4eHh4eHMBQG
    A1UdEQQNMAuCCWxvY2FsaG9zdDAKBggqhkjOPQQDAgNDADBAHBAK3Mgmt38pO7Sq
    iXdOjeW0OqTr6HBgxvBicJcxQ4UeUcCe0LHUvjLhNoWzejc6Av9CzyXcXedZcBH9
    86YpNA==
    -----END CERTIFICATE-----
    """
)

let server = HttpServer()
TLSSocket.configure(tlsConfiguration)
server.secureSocketType = TLSSocket.self
try server.start(8082, forceIPv4: true)

server.middleware.append { request, header in
    print("Request \(request.id) \(request.method) \(request.path) from \(request.clientIP ?? "")")
    request.onFinished { summary in
        print("Request \(summary.requestID) finished with \(summary.responseCode) [\(summary.responseSize)] in \(String(format: "%.3f", summary.durationInSeconds)) seconds")
    }
    return nil
}
server.get["/"] = { request, headers in
        .ok(.text("Hello, World!"))
}
Process.watchSignals{ _ in
    server.stop()
}

RunLoop.main.run()
