import BigInt
import Foundation
import OSLog
import web3
import secp256k1

public class SessionManager {
    private var sessionServerBaseUrl = "https://broadcast-server.tor.us/"
    private var sessionID: secp256k1.KeyAgreement.PrivateKey? {
        didSet {
            if let sessionID = sessionID {
                KeychainManager.shared.save(key: .sessionID, val: sessionID.rawRepresentation.toHexString())
            }
        }
    }

    private let sessionNamespace: String = ""
    private let sessionTime: Int

    public func getSessionID() -> secp256k1.KeyAgreement.PrivateKey? {
        return sessionID
    }

    public func setSessionID(_ val: secp256k1.KeyAgreement.PrivateKey) {
        sessionID = val
    }
    
    public init(sessionServerBaseUrl: String? = nil, sessionTime: Int = 86400, sessionID: String? = nil) throws {
        if let sessionID = sessionID {
            guard let data = Data(hexString: sessionID) else {
                throw SessionManagerError.runtimeError("Invalid sessionID")
            }
            let key = try secp256k1.KeyAgreement.PrivateKey(dataRepresentation: data, format: .uncompressed)
            self.sessionID = key
        } else {
            if let sessionID = KeychainManager.shared.get(key: .sessionID) {
                guard let data = Data(hexString: sessionID) else {
                    throw SessionManagerError.runtimeError("Invalid sessionID")
                }
                self.sessionID = try secp256k1.KeyAgreement.PrivateKey(dataRepresentation: data, format: .uncompressed)
            }
        }
        if let sessionServerBaseUrl = sessionServerBaseUrl {
            self.sessionServerBaseUrl = sessionServerBaseUrl
        }
        self.sessionTime = min(sessionTime, 7 * 86400)
        Router.baseURL = self.sessionServerBaseUrl
    }

    private func generateRandomSessionID() throws -> secp256k1.KeyAgreement.PrivateKey {
        return try generatePrivateKey()
    }

    public func createSession<T: Encodable>(data: T) async throws -> String {
        do {
            let sessionID: secp256k1.KeyAgreement.PrivateKey
            do { sessionID = try generateRandomSessionID() } catch (_) { throw SessionManagerError.sessionIDAbsent }
            self.sessionID = sessionID
            let publicKey = sessionID.publicKey
            let encodedObj = try JSONEncoder().encode(data)
            let jsonString = String(data: encodedObj, encoding: .utf8) ?? ""
            let encData = try encryptData(privkey: sessionID, jsonString)
            let sig = try secp256k1.sign(privkey: secp256k1.Signing.PrivateKey(dataRepresentation: sessionID.rawRepresentation, format: .uncompressed), messageData: encData)
            let sigData = try JSONEncoder().encode(sig)
            let sigJsonStr = String(data: sigData, encoding: .utf8) ?? ""
            let sessionRequestModel = SessionRequestModel(key: publicKey.dataRepresentation.toHexString(), data: encData, signature: sigJsonStr, timeout: sessionTime)
            let api = Router.set(T: sessionRequestModel)
            let result = await Service.request(router: api)
            switch result {
            case let .success(data):
                let msgDict = try JSONSerialization.jsonObject(with: data)
                os_log("authrorize session response is: %@", log: getTorusLogger(log: Web3AuthLogger.network, type: .info), type: .info, "\(msgDict)")
                return sessionID.rawRepresentation.toHexString()
            case let .failure(error):
                throw error
            }
        } catch {
            throw error
        }
    }

    public func authorizeSession() async throws -> [String: Any] {
        guard let sessionID = sessionID else {
            throw SessionManagerError.sessionIDAbsent
        }
        let publicKey = sessionID.publicKey
        let api = Router.get([.init(name: "key", value: "\(publicKey.dataRepresentation.toHexString())"), .init(name: "namespace", value: sessionNamespace)])
        let result = await Service.request(router: api)
        switch result {
        case let .success(data):
            do {
                let msgDict = try JSONSerialization.jsonObject(with: data) as? [String: String]
                let msgData = msgDict?["message"]
                os_log("authrorize session response is: %@", log: getTorusLogger(log: Web3AuthLogger.network, type: .info), type: .info, "\(String(describing: msgDict))")
                let loginDetails = try decryptData(privKey: sessionID, d: msgData ?? "")
                KeychainManager.shared.save(key: .sessionID, val: sessionID.rawRepresentation.toHexString())
                return loginDetails
            } catch {
                throw error
            }
        case let .failure(error):
            throw error
        }
    }

    public func invalidateSession() async throws -> Bool {
        guard let sessionID = sessionID else {
            throw SessionManagerError.sessionIDAbsent
        }
        do {
            let publicKey = sessionID.publicKey
            let encData = try encryptData(privkey: sessionID, "")
            let sig = try secp256k1.sign(privkey: secp256k1.Signing.PrivateKey(dataRepresentation: sessionID.rawRepresentation, format: .uncompressed), messageData: encData)
            let sigData = try JSONEncoder().encode(sig)
            let sigJsonStr = String(data: sigData, encoding: .utf8) ?? ""
            let sessionLogoutDataModel = SessionRequestModel(key: publicKey.dataRepresentation.toHexString(), data: encData, signature: sigJsonStr, timeout: 1)
            let api = Router.set(T: sessionLogoutDataModel)
            let result = await Service.request(router: api)
            switch result {
            case let .success(data):
                do {
                    let msgDict = try JSONSerialization.jsonObject(with: data)
                    os_log("logout response is: %@", log: getTorusLogger(log: Web3AuthLogger.network, type: .info), type: .info, "\(msgDict)")
                    KeychainManager.shared.delete(key: .sessionID)
                    return true
                } catch {
                    throw error
                }
            case let .failure(error):
                throw error
            }
        } catch let error {
            throw error
        }
    }
}
