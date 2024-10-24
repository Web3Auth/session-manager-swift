import Foundation

#if canImport(curvelib)
    import curvelib
#endif

public final class PublicKeyCollection {
    private(set) var pointer: OpaquePointer?

    public init() {
        pointer = curve_secp256k1_public_key_collection_new()
    }

    public func insert(key: PublicKey) throws {
        var errorCode: Int32 = -1
        withUnsafeMutablePointer(to: &errorCode, { error in
            curve_secp256k1_public_key_collection_add(pointer, key.pointer, error)
        })
        guard errorCode == 0 else {
            throw CurveError(code: errorCode)
        }
    }

    deinit {
        curve_secp256k1_public_key_collection_free(pointer)
    }
}
