import Foundation

extension Data {
    init?(hexString: String) {
        let length = hexString.count / 2
        var data = Data(capacity: length)
        for i in 0 ..< length {
            let j = hexString.index(hexString.startIndex, offsetBy: i * 2)
            let k = hexString.index(j, offsetBy: 2)
            let bytes = hexString[j ..< k]
            if var byte = UInt8(bytes, radix: 16) {
                data.append(&byte, count: 1)
            } else {
                return nil
            }
        }
        self = data
    }

    func addLeading0sForLength64() -> Data {
        Data(hex: toHexString().addLeading0sForLength64())
    }
    
    func toBytes() -> [UInt8] {
        Array(self)
    }

    static func randomOfLength(_ length: Int) -> Data? {
        var data = [UInt8](repeating: 0, count: length)
        let result = SecRandomCopyBytes(kSecRandomDefault,
                                        data.count,
                                        &data)
        if result == errSecSuccess {
            return Data(data)
        }

        return nil
    }
}
