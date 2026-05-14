import Foundation
import Swifter
import SwifterTLS


let server = HttpServer()
server.secureSocketType = TLSSocket.self
try server.start(8082, forceIPv4: true)

server.middleware.append { request, header in
    print("Request \(request.id) \(request.method) \(request.path) from \(request.clientIP ?? "")")
    request.onFinished { summary in
        print("Request \(summary.requestID) finished with \(summary.responseCode) [\(summary.responseSize)] in \(String(format: "%.3f", summary.durationInSeconds)) seconds")
    }
    return nil
}
Process.watchSignals{ _ in
    server.stop()
}

RunLoop.main.run()
