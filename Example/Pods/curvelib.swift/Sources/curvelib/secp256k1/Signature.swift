import Foundation

#if canImport(curvelib)
    import curvelib
#endif

public final class Signature {
    private(set) var pointer: OpaquePointer?

    internal init(ptr: OpaquePointer) {
        pointer = ptr
    }

    public init(hex: String) throws {
        var errorCode: Int32 = -1
        let hexPtr = UnsafeMutablePointer<Int8>(mutating: (hex as NSString).utf8String)
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            curve_secp256k1_ecdsa_signature_parse(hexPtr, error)
        })
        guard errorCode == 0 else {
            throw CurveError(code: errorCode)
        }
        pointer = result
    }

    public func serialize() throws -> String {
        var errorCode: Int32 = -1
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            curve_secp256k1_ecdsa_signature_serialize(pointer, error)
        })
        guard errorCode == 0 else {
            throw CurveError(code: errorCode)
        }
        let value = String(cString: result!)
        curve_secp256k1_string_free(result)
        return value
    }
    
    public func serialize_der() throws -> String {
        var errorCode: Int32 = -1
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            curve_secp256k1_ecdsa_signature_serialize_der(pointer, error)
        })
        guard errorCode == 0 else {
            throw CurveError(code: errorCode)
        }
        let value = String(cString: result!)
        curve_secp256k1_string_free(result)
        return value
    }

    deinit {
        curve_secp256k1_signature_free(pointer)
    }
}
