import Foundation

#if canImport(curvelib)
    import curvelib
#endif

public final class ECDH {
    public static func ecdh(sk: SecretKey, pk: PublicKey) throws -> String {
        var errorCode: Int32 = -1
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            curve_secp256k1_ecdh(sk.pointer, pk.pointer, error)
        })
        guard errorCode == 0 else {
            throw CurveError(code: errorCode)
        }
        let value = String(cString: result!)
        curve_secp256k1_string_free(result)
        return value
    }
    
    public static func ecdhStandard(sk: SecretKey, pk: PublicKey) throws -> String {
        var errorCode: Int32 = -1
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            curve_secp256k1_standard_ecdh(sk.pointer, pk.pointer, error)
        })
        guard errorCode == 0 else {
            throw CurveError(code: errorCode)
        }
        let value = String(cString: result!)
        curve_secp256k1_string_free(result)
        return value
    }
}
