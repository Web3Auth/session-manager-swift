import Foundation

public struct Signature: Codable {
    let r: String
    let s: String

    public init(r: String, s: String) {
        self.r = r
        self.s = s
    }
}

struct SessionRequestModel: Codable {
    var key: String
    var data: String
    var signature: String
    var timeout: Int

    public init(key: String, data: String, signature: String, timeout: Int) {
        self.key = key
        self.data = data
        self.signature = signature
        self.timeout = timeout
    }
}

public struct ECIES: Codable {
    public init(iv: String, ephemPublicKey: String, ciphertext: String, mac: String) {
        self.iv = iv
        self.ephemPublicKey = ephemPublicKey
        self.ciphertext = ciphertext
        self.mac = mac
    }
    
    public init(params: String) throws {
        let data = params.data(using: .utf8) ?? Data()
        var arr = Array(repeating: "", count: 4)
        do {
            let dict = try JSONSerialization.jsonObject(with: data) as? [String: String]
            dict?.forEach { key, value in
                if key == "iv" {
                    arr[0] = value
                } else if key == "ephemPublicKey" {
                    arr[1] = value
                } else if key == "ciphertext" {
                    arr[2] = value
                } else if key == "mac" {
                    arr[3] = value
                }
            }
            iv = arr[0]
            ephemPublicKey = arr[1]
            ciphertext = arr[2]
            mac = arr[3]
        } catch let error {
            throw SessionManagerError.runtimeError(error.localizedDescription)
        }
    }

    var iv: String
    var ephemPublicKey: String
    var ciphertext: String
    var mac: String
}
