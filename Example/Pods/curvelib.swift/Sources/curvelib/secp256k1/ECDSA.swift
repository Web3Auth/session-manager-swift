import Foundation

#if canImport(curvelib)
    import curvelib
#endif

public final class ECDSA {
    public static func signRecoverable(key: SecretKey, hash: String) throws -> Signature {
        var errorCode: Int32 = -1
        let hexPtr = UnsafeMutablePointer<Int8>(mutating: (hash as NSString).utf8String)
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            curve_secp256k1_ecdsa_sign_recoverable(key.pointer, hexPtr, error)
        })
        guard errorCode == 0 else {
            throw CurveError(code: errorCode)
        }
        return Signature(ptr: result!)
    }

    public static func recover(signature: Signature, hash: String) throws -> PublicKey {
        var errorCode: Int32 = -1
        let hexPtr = UnsafeMutablePointer<Int8>(mutating: (hash as NSString).utf8String)
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            curve_secp256k1_ecdsa_recover(signature.pointer, hexPtr, error)
        })
        guard errorCode == 0 else {
            throw CurveError(code: errorCode)
        }
        return PublicKey(ptr: result!)
    }
}
