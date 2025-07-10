import Swifter
import SwiftExtensions
import Foundation

public class TLSSocket: SecureSocket {
    private let socket: Socket
    
    public var raw: Socket {
        socket
    }

    public required init(_ socket: Socket) {
        print("New socket")
        self.socket = socket
        
        do {
            let clientHello = try ClientHello(socket)
            socket.close()
        } catch {
            print("Error \(error)")
        }
    }
    
    public func read() throws -> UInt8 {
        try socket.read()
    }
    
    public func readLine() throws -> String {
        try socket.readLine()
    }
    
    public func read(length: Int) throws -> [UInt8] {
        try socket.read(length: length)
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
