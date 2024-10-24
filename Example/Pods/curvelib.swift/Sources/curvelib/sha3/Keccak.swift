import Foundation

#if canImport(curvelib)
    import curvelib
#endif

public func keccak256 ( data : Data ) throws -> Data {
    var errorCode: Int32 = -1
    let hexPtr = UnsafeMutablePointer<Int8>(mutating: (data.hexString  as NSString).utf8String)
    let result = withUnsafeMutablePointer(to: &errorCode, { error in
        curve_sha3_keccak256(hexPtr, error)
    })
    guard errorCode == 0 else {
        throw CurveError(code: errorCode)
    }
    let value = String(cString: result!)
    curve_secp256k1_string_free(result)

    guard let hex_data = Data(hexString: value) else {
        throw CurveError(code: 3)
    }
    return hex_data
}

public enum Variants {
    case KECCAK256
}

public extension Data {
    func sha3( varient : Variants ) throws -> Data {
        return try keccak256(data: self)
    }
}
