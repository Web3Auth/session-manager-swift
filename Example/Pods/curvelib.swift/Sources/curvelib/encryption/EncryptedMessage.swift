import Foundation

#if canImport(curvelib)
    import curvelib
#endif

public final class EncryptedMessage {
    private(set) var pointer: OpaquePointer?

    internal init(ptr: OpaquePointer) {
        pointer = ptr
    }

    public init(cipherText: String, ephemeralPublicKey: PublicKey, iv: String, mac: String) throws {
        var errorCode: Int32 = -1
        let cipherTextPtr = UnsafeMutablePointer<Int8>(mutating: (cipherText as NSString).utf8String)
        let ivPtr = UnsafeMutablePointer<Int8>(mutating: (iv as NSString).utf8String)
        let macPtr = UnsafeMutablePointer<Int8>(mutating: (mac as NSString).utf8String)

        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            curve_secp256k1_encrypted_message_from_components(cipherTextPtr, ephemeralPublicKey.pointer, ivPtr, macPtr, error)
        })
        guard errorCode == 0 else {
            throw CurveError(code: errorCode)
        }
        pointer = result
    }

    public func ephemeralPublicKey() throws -> PublicKey {
        var errorCode: Int32 = -1
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            curve_secp256k1_encrypted_message_get_ephemeral_public_key(pointer, error)
        })
        guard errorCode == 0 else {
            throw CurveError(code: errorCode)
        }
        return PublicKey(ptr: result!)
    }

    public func chipherText() throws -> String {
        var errorCode: Int32 = -1
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            curve_secp256k1_encrypted_message_get_ciphertext(pointer, error)
        })
        guard errorCode == 0 else {
            throw CurveError(code: errorCode)
        }
        let value = String(cString: result!)
        curve_secp256k1_string_free(result)
        return value
    }

    public func iv() throws -> String {
        var errorCode: Int32 = -1
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            curve_secp256k1_encrypted_message_get_iv(pointer, error)
        })
        guard errorCode == 0 else {
            throw CurveError(code: errorCode)
        }
        let value = String(cString: result!)
        curve_secp256k1_string_free(result)
        return value
    }

    public func mac() throws -> String {
        var errorCode: Int32 = -1
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            curve_secp256k1_encrypted_message_get_mac(pointer, error)
        })
        guard errorCode == 0 else {
            throw CurveError(code: errorCode)
        }
        let value = String(cString: result!)
        curve_secp256k1_string_free(result)
        return value
    }

    deinit {
        curve_secp256k1_encrypted_message_free(pointer)
    }
}
