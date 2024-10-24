import Foundation

#if canImport(curvelib)
    import curvelib
#endif

public final class Encryption {
    public static func encrypt(pk: PublicKey, plainText: Data) throws -> EncryptedMessage {
        var errorCode: Int32 = -1
        let stringPtr = UnsafeMutablePointer<Int8>(mutating: (plainText.hexString as NSString).utf8String)
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            curve_secp256k1_aes_cbc_hmac_encrypt(pk.pointer, stringPtr, error)
        })

        guard errorCode == 0 else {
            throw CurveError(code: errorCode)
        }

        return EncryptedMessage(ptr: result!)
    }

    public static func decrypt(sk: SecretKey, encrypted: EncryptedMessage, skipMacCheck: Bool = false) throws -> Data {
        var errorCode: Int32 = -1
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            curve_secp256k1_aes_cbc_hmac_decrypt(sk.pointer, encrypted.pointer, skipMacCheck, error)
        })

        guard errorCode == 0 else {
            throw CurveError(code: errorCode)
        }

        let value = String(cString: result!)
        curve_secp256k1_string_free(result)

        guard let result = Data(hexString: value) else {
            throw CurveError(code: 3)
        }

        return result
    }
}
