import Foundation
import Swifter
import SwifterTLS

private let tlsConfiguration = TLSConfiguration(
    privateKeyPEM: """
    -----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgLxHL+J4cg1R+mnqM
    7SwS0x5Fr1FyDGTSGgQAezqPDXShRANCAAR6mbe54Kpb1haP7CIk7VlCssnCxLAG
    SfSUEm5MtQpA7BrbnPH7aOwlj89yTmhb+TN1a0eEjgK4WKmD0xb36DP5
    -----END PRIVATE KEY-----
    """,
    // first leaf, then intermediate, last root
    certificatePEM: """
    -----BEGIN CERTIFICATE-----
    MIIBmTCCAUSgAwIBAgIJAPg5p4jWM8buMAoGCCqGSM49BAMCMBUxEzARBgNVBAMT
    ClJvb3QgQ0EgUjEwHhcNMjUwNDE0MTA0NDAwWhcNMzUwNDE0MTA0NDAwWjAUMRIw
    EAYDVQQDEwlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR6mbe5
    4Kpb1haP7CIk7VlCssnCxLAGSfSUEm5MtQpA7BrbnPH7aOwlj89yTmhb+TN1a0eE
    jgK4WKmD0xb36DP5o34wfDAdBgNVHQ4EFgQUEhISEhISEhISEhISEhISEhISEhIw
    FAYDVR0RBA0wC4IJbG9jYWxob3N0MEUGA1UdIwQ+MDyAFIeHh4eHh4eHh4eHh4eH
    h4eHh4eHoRmkFzAVMRMwEQYDVQQDEwpSb290IENBIFIxggkA+DmniNYzxrswCgYI
    KoZIzj0EAwIDQwAwQMe3u4wV3csV3sGnbHWynADE50wasRxt67IFWOeg8ti3lW3e
    PBf7zUviqqGzo/BI28g6eFgA2sPsVlUBkkqm24E=
    -----END CERTIFICATE-----
    -----BEGIN CERTIFICATE-----
    MIIBUDCB/KADAgECAgkA+DmniNYzxrswCgYIKoZIzj0EAwIwFTETMBEGA1UEAxMK
    Um9vdCBDQSBSMTAeFw0yNTA0MTQxMDQ0MDBaFw0zNTA0MTQxMDQ0MDBaMBUxEzAR
    BgNVBAMTClJvb3QgQ0EgUjEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASyW8Ar
    hmuq67J7MyQHqBsX6eZW5/nFC1xvCfS0uQzcvT+7m2w8+1vgPnOs+fkSorQrnqAE
    2622pRv4bMCHjb55ozUwMzASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSH
    h4eHh4eHh4eHh4eHh4eHh4eHhzAKBggqhkjOPQQDAgNDADBAktauq8jL/mSgEzyh
    borIV2ZZzCL8726L94NseafSyx2qHYjJYYU0v7oub810/ENFmkn7XGh3d7zhB+jN
    C63WVg==
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
