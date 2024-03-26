import Foundation
import curveSecp256k1

public func dictionaryToStruct<T: Decodable>(_ dictionary: [String: Any]) -> T? {
    guard let jsonData = try? JSONSerialization.data(withJSONObject: dictionary, options: []),
          let structObject = try? JSONDecoder().decode(T.self, from: jsonData) else {
        return nil
    }
    return structObject
}

public func generateRandomData(length: Int) -> Data? {
    return Data.randomOfLength(length)
}

public func generatePrivateKeyData() throws -> Data? {
    return Data( hex: try curveSecp256k1.SecretKey().serialize())
}

func decodedBase64(_ base64URLSafe: String) -> Data? {
    var base64 = base64URLSafe
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    if base64.count % 4 != 0 {
        base64.append(String(repeating: "=", count: 4 - base64.count % 4))
    }
    return Data(base64Encoded: base64)
}

func tupleToArray(_ tuple: Any) -> [UInt8] {
    // var result = [UInt8]()
    let tupleMirror = Mirror(reflecting: tuple)
    let tupleElements = tupleMirror.children.map({ $0.value as! UInt8 })
    return tupleElements
}

func array32toTuple(_ arr: [UInt8]) -> (UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8, UInt8) {
    return (arr[0] as UInt8, arr[1] as UInt8, arr[2] as UInt8, arr[3] as UInt8, arr[4] as UInt8, arr[5] as UInt8, arr[6] as UInt8, arr[7] as UInt8, arr[8] as UInt8, arr[9] as UInt8, arr[10] as UInt8, arr[11] as UInt8, arr[12] as UInt8, arr[13] as UInt8, arr[14] as UInt8, arr[15] as UInt8, arr[16] as UInt8, arr[17] as UInt8, arr[18] as UInt8, arr[19] as UInt8, arr[20] as UInt8, arr[21] as UInt8, arr[22] as UInt8, arr[23] as UInt8, arr[24] as UInt8, arr[25] as UInt8, arr[26] as UInt8, arr[27] as UInt8, arr[28] as UInt8, arr[29] as UInt8, arr[30] as UInt8, arr[31] as UInt8, arr[32] as UInt8, arr[33] as UInt8, arr[34] as UInt8, arr[35] as UInt8, arr[36] as UInt8, arr[37] as UInt8, arr[38] as UInt8, arr[39] as UInt8, arr[40] as UInt8, arr[41] as UInt8, arr[42] as UInt8, arr[43] as UInt8, arr[44] as UInt8, arr[45] as UInt8, arr[46] as UInt8, arr[47] as UInt8, arr[48] as UInt8, arr[49] as UInt8, arr[50] as UInt8, arr[51] as UInt8, arr[52] as UInt8, arr[53] as UInt8, arr[54] as UInt8, arr[55] as UInt8, arr[56] as UInt8, arr[57] as UInt8, arr[58] as UInt8, arr[59] as UInt8, arr[60] as UInt8, arr[61] as UInt8, arr[62] as UInt8, arr[63] as UInt8)
}

extension Array where Element == UInt8 {
    func uint8Reverse() -> Array {
        var revArr = [Element]()
        for arrayIndex in stride(from: count - 1, through: 0, by: -1) {
            revArr.append(self[arrayIndex])
        }
        return revArr
    }
}
