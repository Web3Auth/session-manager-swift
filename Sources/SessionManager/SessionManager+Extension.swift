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

//    private func encrypt(publicKey: String, msg: String, opts: ECIES?) throws -> ECIES {
//        guard let ephemPrivateKey = generatePrivateKeyData(), let ephemPublicKey = SECP256K1.privateToPublic(privateKey: ephemPrivateKey)
//        else {
//            throw SessionManagerError.runtimeError("Private key generation failed")
//        }
//        let ephermalPublicKey = publicKey.strip04Prefix()
//        let ephermalPublicKeyBytes = ephermalPublicKey.hexa
//        var ephermOne = ephermalPublicKeyBytes.prefix(32)
//        var ephermTwo = ephermalPublicKeyBytes.suffix(32)
//        ephermOne.reverse(); ephermTwo.reverse()
//        ephermOne.append(contentsOf: ephermTwo)
//        
//        let ephermSecret = try SecretKey(hex: ephermOne.hexa)
//        let ephemPubKey = shareSecret.toPublic()
//        
//        let curveSecret
//        guard
//            // Calculate g^a^b, i.e., Shared Key
//            //  let data = inprivateKey
//            let sharedSecret = SECP256K1.ecdh(pubKey: ephemPubKey, privateKey: ephemPrivateKey)
//        else {
//            throw SessionManagerError.runtimeError("ECDH error")
//        }
//
//        let sharedSecretData = sharedSecret.data
//        let sharedSecretPrefix = Array(tupleToArray(sharedSecretData).prefix(32))
//        let reversedSharedSecret = sharedSecretPrefix.uint8Reverse()
//        let hash = SHA2(variant: .sha512).calculate(for: Array(reversedSharedSecret))
//        let iv: [UInt8] = (opts?.iv ?? SECP256K1.randomBytes(length: 16)?.toHexString())?.hexa ?? []
//        let encryptionKey = Array(hash.prefix(32))
//        let macKey = Array(hash.suffix(32))
//        do {
//            // AES-CBCblock-256
//            let aes = try AES(key: encryptionKey, blockMode: CBC(iv: iv), padding: .pkcs7)
//            let encrypt = try aes.encrypt(msg.web3.bytes)
//            let data = Data(encrypt)
//            let ciphertext = data
//            var dataToMac: [UInt8] = iv
//            dataToMac.append(contentsOf: [UInt8](ephemPublicKey.data))
//            dataToMac.append(contentsOf: [UInt8](ciphertext.data))
//            let mac = try? HMAC(key: macKey, variant: .sha2(.sha256)).authenticate(dataToMac)
//            return .init(iv: iv.toHexString(), ephemPublicKey: ephemPublicKey.toHexString(),
//                         ciphertext: ciphertext.toHexString(), mac: mac?.toHexString() ?? "")
//        } catch let err {
//            throw err
//        }
//    }
//
//    private func decrypt(privateKey: String, opts: ECIES) throws -> String {
//        var result: String = ""
//        let ephermalPublicKey = opts.ephemPublicKey.strip04Prefix()
//        let ephermalPublicKeyBytes = ephermalPublicKey.hexa
//        var ephermOne = ephermalPublicKeyBytes.prefix(32)
//        var ephermTwo = ephermalPublicKeyBytes.suffix(32)
//        ephermOne.reverse(); ephermTwo.reverse()
//        ephermOne.append(contentsOf: ephermTwo)
//        let ephemPubKey = secp256k1_pubkey.init(data: array32toTuple(Array(ephermOne)))
//        guard
//            // Calculate g^a^b, i.e., Shared Key
//            let data = Data(hexString: privateKey),
//            let sharedSecret = SECP256K1.ecdh(pubKey: ephemPubKey, privateKey: data)
//        else {
//            throw SessionManagerError.runtimeError("ECDH Error")
//        }
//        let sharedSecretData = sharedSecret.data
//        let sharedSecretPrefix = Array(tupleToArray(sharedSecretData).prefix(32))
//        let reversedSharedSecret = sharedSecretPrefix.uint8Reverse()
//        let hash = SHA2(variant: .sha512).calculate(for: Array(reversedSharedSecret))
//        let aesEncryptionKey = Array(hash.prefix(32))
//        let iv = opts.iv.hexa
//        let macKey = Array(hash.suffix(32))
//        var dataToMac: [UInt8] = opts.iv.hexa
//        dataToMac.append(contentsOf: [UInt8](opts.ephemPublicKey.hexa))
//        dataToMac.append(contentsOf: [UInt8](opts.ciphertext.hexa))
//        do {
//            let macGood = try? HMAC(key: macKey, variant: .sha2(.sha256)).authenticate(dataToMac)
//            let macData = opts.mac.hexa
//            if macGood != macData {
//                throw SessionManagerError.runtimeError("Bad MAC error during decrypt")
//            }
//            // AES-CBCblock-256
//            let aes = try AES(key: aesEncryptionKey, blockMode: CBC(iv: iv), padding: .pkcs7)
//            let decrypt = try aes.decrypt(opts.ciphertext.hexa)
//            let data = Data(decrypt)
//            result = String(data: data, encoding: .utf8) ?? ""
//        } catch let err {
//            throw err
//        }
//        return result
//    }
}
