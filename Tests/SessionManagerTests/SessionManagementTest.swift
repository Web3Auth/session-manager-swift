@testable import SessionManager
import XCTest
import secp256k1

struct SFAModel: Codable {
    let publicKey: String
    let privateKey: String
}

final class SessionManagementTest: XCTestCase {
    var sessionID: String = "ab6fb847033ccb155769bcd1193d0da2096fb3419193725e5a48b7d40e65caa3"

    private func generatePrivateandPublicKey() throws -> (privKey: String, pubKey: String) {
        let privKey = try generatePrivateKey()
        let publicKey = privKey.publicKey
        return (privKey: privKey.rawRepresentation.toHexString(), pubKey: publicKey.dataRepresentation.toHexString())
    }

    func test_createSessionID() async throws {
        let session = try SessionManager()
        let (privKey, pubKey) = try generatePrivateandPublicKey()
        let sfa = SFAModel(publicKey: pubKey, privateKey: privKey)
        let _ = try await session.createSession(data: sfa)
    }

    func test_authoriseSessionID() async throws {
        let session = try SessionManager()
        let (privKey, pubKey) = try generatePrivateandPublicKey()
        let sfa = SFAModel(publicKey: pubKey, privateKey: privKey)
        let created = try await session.createSession(data: sfa)
        XCTAssertFalse(created.isEmpty)
        let auth = try await session.authorizeSession()
        XCTAssertTrue(auth.keys.contains("privateKey"))
        XCTAssertTrue(auth.keys.contains("publicKey"))
    }

    func testEncryptDecryptData() throws {
        let session = try SessionManager()
        let privKey = try secp256k1.KeyAgreement.PrivateKey(dataRepresentation: Data(hexString: "dda863b615ac6de27fb680b5563db3c19176a6f42cc1dee1768e220983385e3e")!, format: .uncompressed)
        let dt = ["data": "data"]
        let dataToEncrypt = try JSONSerialization.data(withJSONObject: dt)
        let dataToEncryptStr = String(data: dataToEncrypt, encoding: .utf8)!
        let encryptdata = try session.encryptData(privkey: privKey, dataToEncryptStr)
        let decrypted = try session.decryptData(privKey: privKey, d: encryptdata)
        let decryptedToString = String(data: try JSONSerialization.data(withJSONObject: decrypted), encoding: .utf8)!
        XCTAssertEqual(dataToEncryptStr, decryptedToString)
    }

    func testSign() throws {
        let privKey = try secp256k1.Signing.PrivateKey(dataRepresentation: Data(hexString: "bce6550a433b2e38067501222f9e75a2d4c5a433a6d27ec90cd81fbd4194cc2b")!, format: .uncompressed)
        let encData = "test data"
        let sig = try SECP256K1().sign(privkey: privKey, messageData: encData)
        XCTAssertEqual(sig.r, "d7736799107d8e6308af995d827dc8772993cd8ccab5c230fe8277cecb02f31a")
        XCTAssertEqual(sig.s, "4df631a4059f45d8cb0e8889ff1b8096243796189ec00440883b1c0271a19e80")
    }

    func testEncryptAndSign() throws {
        let privKey = try secp256k1.Signing.PrivateKey(dataRepresentation: Data(hexString: "dda863b615ac6de27fb680b5563db3c19176a6f42cc1dee1768e220983385e3e")!, format: .uncompressed)
        let encdata = "{\"iv\":\"693407372626b11017d0ec30acd29e6a\",\"ciphertext\":\"cbe09442851a0463b3e34e2f912c6aee\",\"ephemPublicKey\":\"0477e20c5d9e3281a4eca7d07c1c4cc9765522ea7966cd7ea8f552da42049778d4fcf44b35b59e84eddb1fa3266350e4f2d69d62da82819d51f107550e03852661\",\"mac\":\"96d358f46ef371982af600829c101e78f6c5d5f960bd96fdd2ca52763ee50f65\"}"
        let sig = try SECP256K1().sign(privkey: privKey, messageData: encdata)
        XCTAssertEqual(sig.r, "b0161b8abbd66da28734d105e28455bf9a48a33ee1dfde71f96e2e9197175650")
        XCTAssertEqual(sig.s, "4d53303ec05596ca6784cff1d25eb0e764f70ff5e1ce16a896ec58255b25b5ff")
    }

    func test_invalidateSession() async throws {
        let session = try SessionManager(sessionID: sessionID)
        let invalidated = try await session.invalidateSession()
        XCTAssertEqual(invalidated, true)
    }
}
