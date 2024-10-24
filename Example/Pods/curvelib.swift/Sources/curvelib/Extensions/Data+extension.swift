import Foundation

public extension Data {
    var hexString: String {
        return map { String(format: "%02x", $0) }.joined()
    }
    
    init?(hexString: String) {
        // Ensure the string has an even number of characters
        guard hexString.count % 2 == 0 else { return nil }

        var data = Data(capacity: hexString.count / 2)

        // Convert each pair of characters to a byte and append to data
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let nextIndex = hexString.index(index, offsetBy: 2)
            if let byte = UInt8(hexString[index..<nextIndex], radix: 16) {
                data.append(byte)
            } else {
                return nil // Invalid hexadecimal character
            }
            index = nextIndex
        }

        self = data
    }
}
