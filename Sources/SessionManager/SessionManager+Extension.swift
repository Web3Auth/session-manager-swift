//
//  SessionManagement+Extension.swift
//  Web3Auth
//
//  Created by Dhruv Jaiswal on 03/10/22.
//

import CryptoSwift
import Foundation
import curveSecp256k1
import encryption_aes_cbc_sha512

extension SessionManager {
    func decryptData(privKeyHex: String, d: String) throws -> [String: Any] {
        let secretKey = try curveSecp256k1.SecretKey(hex: privKeyHex)
        let data = d.data(using: .utf8) ?? Data()
        let ecies = try JSONDecoder().decode(ECIES.self, from: data)
        
        let encrytedFormat = try EncryptedMessage(cipherText: ecies.ciphertext, ephemeralPublicKey: curveSecp256k1.PublicKey(hex: ecies.ephemPublicKey), iv: ecies.iv, mac: ecies.mac)
        
        let result = try encryption_aes_cbc_sha512.Encryption.decrypt(sk: secretKey, encrypted: encrytedFormat)
        
        guard let dict = try JSONSerialization.jsonObject(with: result.data(using: .utf8) ?? Data()) as? [String: Any] else { throw SessionManagerError.decodingError }
        return dict
    }

    func encryptData(privkeyHex: String, _ dataToEncrypt: String) throws -> String {
        let secretKey = try curveSecp256k1.SecretKey(hex: privkeyHex)
        let pubKey = try secretKey.toPublic().serialize(compressed: false)
        
        let encParams = try encryption_aes_cbc_sha512.Encryption.encrypt(pk: secretKey.toPublic(), plainText: dataToEncrypt)
        
        let ecies : ECIES = try .init(iv: encParams.iv(), ephemPublicKey: encParams.ephemeralPublicKey().serialize(compressed: false), ciphertext: encParams.chipherText(), mac: encParams.mac())
        let data = try JSONEncoder().encode(ecies)
        guard let string = String(data: data, encoding: .utf8) else { throw SessionManagerError.runtimeError("Invalid String from enc Params") }
        return string
    }

    // why do we need this function??
    private func encParamsBufToHex(encParamsHex: ECIES) throws -> ECIES {
        let iv = encParamsHex.iv
        let ephemPublicKey = encParamsHex.ephemPublicKey
          let ciphertext = encParamsHex.ciphertext
          let mac = encParamsHex.mac
        
        return .init(iv: iv, ephemPublicKey: ephemPublicKey, ciphertext: ciphertext, mac: mac)
    }

    private func encParamsHexToBuf(encParamsHex: String) throws -> ECIES {
        let data = encParamsHex.data(using: .utf8) ?? Data()
        var arr = Array(repeating: "", count: 4)
        do {
            let dict = try JSONSerialization.jsonObject(with: data) as? [String: String]
            dict?.forEach { key, value in
                if key == "iv" {
                    arr[0] = value
                } else if key == "ephemPublicKey" {
                    arr[1] = value
                } else if key == "ciphertext" {
                    arr[2] = value
                } else if key == "mac" {
                    arr[3] = value
                }
            }
            return ECIES(iv: arr[0], ephemPublicKey: arr[1], ciphertext: arr[2], mac: arr[3])
        } catch let error {
            throw SessionManagerError.runtimeError(error.localizedDescription)
        }
    }
}
