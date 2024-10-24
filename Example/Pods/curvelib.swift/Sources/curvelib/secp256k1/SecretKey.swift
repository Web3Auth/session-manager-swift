import Foundation

#if canImport(curvelib)
    import curvelib
#endif

public final class SecretKey {
    private(set) public var pointer: OpaquePointer?

    public init() {
        pointer = curve_secp256k1_private_key_generate()
    }

    internal init(ptr: OpaquePointer) {
        pointer = ptr
    }

    public init(hex: String) throws {
        var errorCode: Int32 = -1
        let hexPtr = UnsafeMutablePointer<Int8>(mutating: (hex as NSString).utf8String)
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            curve_secp256k1_private_key_parse(hexPtr, error)
        })
        guard errorCode == 0 else {
            throw CurveError(code: errorCode)
        }
        pointer = result
    }

    public func addAssign(key: SecretKey) throws {
        var errorCode: Int32 = -1
        withUnsafeMutablePointer(to: &errorCode, { error in
            curve_secp256k1_private_key_tweak_add_assign(pointer, key.pointer, error)
        })
        guard errorCode == 0 else {
            throw CurveError(code: errorCode)
        }
    }

    public func mulAssign(key: SecretKey) throws {
        var errorCode: Int32 = -1
        withUnsafeMutablePointer(to: &errorCode, { error in
            curve_secp256k1_private_key_tweak_mul_assign(pointer, key.pointer, error)
        })
        guard errorCode == 0 else {
            throw CurveError(code: errorCode)
        }
    }

    public func invAssign() throws {
        var errorCode: Int32 = -1
        withUnsafeMutablePointer(to: &errorCode, { error in
            curve_secp256k1_private_key_inv_assign(pointer, error)
        })
        guard errorCode == 0 else {
            throw CurveError(code: errorCode)
        }
    }

    public func inv() throws -> SecretKey {
        var errorCode: Int32 = -1
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            curve_secp256k1_private_key_inv(pointer, error)
        })
        guard errorCode == 0 else {
            throw CurveError(code: errorCode)
        }
        return SecretKey(ptr: result!)
    }

    public func toPublic() throws -> PublicKey {
        var errorCode: Int32 = -1
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            curve_secp256k1_private_key_to_public_key(pointer, error)
        })
        guard errorCode == 0 else {
            throw CurveError(code: errorCode)
        }
        return PublicKey(ptr: result!)
    }

    public func serialize() throws -> String {
        var errorCode: Int32 = -1
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            curve_secp256k1_private_key_serialize(pointer, error)
        })
        guard errorCode == 0 else {
            throw CurveError(code: errorCode)
        }
        let value = String(cString: result!)
        curve_secp256k1_string_free(result)
        return value
    }

    deinit {
        curve_secp256k1_private_key_free(pointer)
    }
}
