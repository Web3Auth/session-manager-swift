//
//  File.swift
//
//
//  Created by Dhruv Jaiswal on 18/07/22.
//
import Foundation
import OSLog
import curveSecp256k1

public class SessionManager {
    private var sessionServerBaseUrl = "https://session.web3auth.io/"
    private var sessionID: String? {
        didSet {
            if let sessionID = sessionID {
                KeychainManager.shared.save(key: .sessionID, val: sessionID)
            }
        }
    }

    private let sessionNamespace: String = ""
    private let sessionTime: Int

    public func getSessionID() -> String? {
        return sessionID
    }

    public func setSessionID(_ val: String) {
        sessionID = val
    }

    public init(sessionServerBaseUrl: String? = nil, sessionTime: Int = 86400, sessionID: String? = nil) {
        if let sessionID = sessionID {
            self.sessionID = sessionID
        } else {
            if let sessionID = KeychainManager.shared.get(key: .sessionID) {
                self.sessionID = sessionID
            }
        }
        if let sessionServerBaseUrl = sessionServerBaseUrl {
            self.sessionServerBaseUrl = sessionServerBaseUrl
        }
        self.sessionTime = min(sessionTime, 7 * 86400)
        Router.baseURL = self.sessionServerBaseUrl
    }

    private func generateRandomSessionID() throws -> String? {
        if let val = try generatePrivateKeyData()?.toHexString().padStart(toLength: 64, padString: "0") {
            return val
        }
        return nil
    }

    public func createSession<T: Encodable>(data: T) async throws -> String {
        do {
            guard let sessionID = try generateRandomSessionID() else { throw SessionManagerError.sessionIDAbsent }
            self.sessionID = sessionID
//            let privKey = sessionID.hexa
            let sessionSecret = try curveSecp256k1.SecretKey(hex: sessionID)
//            let pubkey = try sessionSecret.toPublic().serialize(compressed: false)
            
            let publicKeyHex = try sessionSecret.toPublic().serialize(compressed: false)
            
            let encodedObj = try JSONEncoder().encode(data)
            let jsonString = String(data: encodedObj, encoding: .utf8) ?? ""
            let encData = try encryptData(privkeyHex: sessionID, jsonString)
            
            let hashData = encData.sha3(.keccak256)
            
            let sig = try curveSecp256k1.ECDSA.signRecoverable(key: sessionSecret, hash: hashData).serialize()
            let sigRS = [
                "r" : sig.suffix(130).prefix(64),
                "s" : sig.suffix(66).prefix(64)
            ]
//            let sigData = try JSONEncoder().encode(sigRS)
            let sigData = try JSONSerialization.data(withJSONObject: sigRS)
            let sigJsonStr = String(data: sigData, encoding: .utf8) ?? ""
            let sessionRequestModel = SessionRequestModel(key: publicKeyHex, data: encData, signature: sigJsonStr, timeout: sessionTime)
            let api = Router.set(T: sessionRequestModel)
            let result = await Service.request(router: api)
            switch result {
            case let .success(data):
                let msgDict = try JSONSerialization.jsonObject(with: data)
                os_log("authrorize session response is: %@", log: getTorusLogger(log: Web3AuthLogger.network, type: .info), type: .info, "\(msgDict)")
                return sessionID
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
        let sessionSecret = try curveSecp256k1.SecretKey(hex: sessionID)
        
        let publicKeyHex = try sessionSecret.toPublic().serialize(compressed: false)
        
        let api = Router.get([.init(name: "key", value: "\(publicKeyHex)"), .init(name: "namespace", value: sessionNamespace)])
        let result = await Service.request(router: api)
        switch result {
        case let .success(data):
            do {
                let msgDict = try JSONSerialization.jsonObject(with: data) as? [String: String]
                let msgData = msgDict?["message"]
                os_log("authrorize session response is: %@", log: getTorusLogger(log: Web3AuthLogger.network, type: .info), type: .info, "\(String(describing: msgDict))")
                let loginDetails = try decryptData(privKeyHex: sessionID, d: msgData ?? "")
                KeychainManager.shared.save(key: .sessionID, val: sessionID)
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
            let privKey = try curveSecp256k1.SecretKey(hex: sessionID)
            let publicKeyHex = try privKey.toPublic().serialize(compressed: false)
                    
            let encData = try encryptData(privkeyHex: sessionID, "")
            let hashData = encData.sha3(.keccak256)
            let sig = try curveSecp256k1.ECDSA.signRecoverable(key: privKey, hash: hashData).serialize()
            
            let sigRS = [
                "r" : sig.suffix(130).prefix(64),
                "s" : sig.suffix(66).prefix(64)
            ]
//            let sigData = try JSONEncoder().encode(sigRS)
            let sigData = try JSONSerialization.data(withJSONObject: sigRS)
            let sigJsonStr = String(data: sigData, encoding: .utf8) ?? ""
            let sessionLogoutDataModel = SessionRequestModel(key: publicKeyHex, data: encData, signature: sigJsonStr, timeout: 1)
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
