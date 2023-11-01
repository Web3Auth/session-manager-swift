import CryptoSwift
import Foundation
import secp256k1

extension SessionManager {
    func decryptData(privKey: secp256k1.KeyAgreement.PrivateKey, d: String) throws -> [String: Any] {
        let ecies = try ECIES(params: d)
        let result = try decrypt(privateKey: privKey, opts: ecies)
        guard let dict = try JSONSerialization.jsonObject(with: result.data(using: .utf8) ?? Data()) as? [String: Any] else { throw SessionManagerError.decodingError }
        return dict
    }

    func encryptData(privkey: secp256k1.KeyAgreement.PrivateKey, _ dataToEncrypt: String) throws -> String {
        let pubKey = privkey.publicKey
        let encParams = try encrypt(publicKey: pubKey, msg: dataToEncrypt, opts: nil)
        let data = try JSONEncoder().encode(encParams)
        guard let string = String(data: data, encoding: .utf8) else { throw SessionManagerError.runtimeError("Invalid String from enc Params") }
        return string
    }

    private func encrypt(publicKey: secp256k1.KeyAgreement.PublicKey, msg: String, opts: ECIES?) throws -> ECIES {
        let ephemPrivateKey = try generatePrivateKey()
        let ephemPublicKey = ephemPrivateKey.publicKey
        let ephermalPublicKey = publicKey.dataRepresentation.toHexString().strip04Prefix()
        let ephermalPublicKeyBytes = ephermalPublicKey.hexa
        var ephermOne = ephermalPublicKeyBytes.suffix(64).prefix(32)
        var ephermTwo = ephermalPublicKeyBytes.suffix(32)
        ephermOne.reverse(); ephermTwo.reverse()
        ephermOne.append(contentsOf: ephermTwo)
        let ephemPubKey = secp256k1_pubkey.init(data: array32toTuple(Array(ephermOne)))
        guard
            // Calculate g^a^b, i.e., Shared Key
            //  let data = inprivateKey
            let sharedSecret = secp256k1.ecdh(pubKey: ephemPubKey, privateKey: ephemPrivateKey.rawRepresentation)
        else {
            throw SessionManagerError.runtimeError("ECDH error")
        }

        let sharedSecretData = sharedSecret.data
        let sharedSecretPrefix = Array(tupleToArray(sharedSecretData).prefix(32))
        let reversedSharedSecret = sharedSecretPrefix.uint8Reverse()
        let hash = SHA2(variant: .sha512).calculate(for: Array(reversedSharedSecret))
        let iv: [UInt8] = (opts?.iv ?? generateRandomData(length: 16)?.toHexString())?.hexa ?? []
        let encryptionKey = Array(hash.prefix(32))
        let macKey = Array(hash.suffix(32))
        do {
            // AES-CBCblock-256
            let aes = try AES(key: encryptionKey, blockMode: CBC(iv: iv), padding: .pkcs7)
            let encrypt = try aes.encrypt(msg.web3.bytes)
            let data = Data(encrypt)
            let ciphertext = data
            var dataToMac: [UInt8] = iv
            dataToMac.append(contentsOf: [UInt8](ephemPublicKey.dataRepresentation[1...64]))
            dataToMac.append(contentsOf: [UInt8](ciphertext.data))
            let mac = try? HMAC(key: macKey, variant: .sha2(.sha256)).authenticate(dataToMac)
            return .init(iv: iv.toHexString(), ephemPublicKey: ephemPublicKey.dataRepresentation[1...64].toHexString(),
                         ciphertext: ciphertext.toHexString(), mac: mac?.toHexString() ?? "")
        } catch let err {
            throw err
        }
    }

    private func decrypt(privateKey: secp256k1.KeyAgreement.PrivateKey, opts: ECIES) throws -> String {
        var result: String = ""
        let ephermalPublicKey = opts.ephemPublicKey.strip04Prefix()
        let ephermalPublicKeyBytes = ephermalPublicKey.hexa
        var ephermOne = ephermalPublicKeyBytes.prefix(32)
        var ephermTwo = ephermalPublicKeyBytes.suffix(32)
        ephermOne.reverse(); ephermTwo.reverse()
        ephermOne.append(contentsOf: ephermTwo)
        let ephemPubKey = secp256k1_pubkey.init(data: array32toTuple(Array(ephermOne)))
        let data = privateKey.rawRepresentation
        guard
            // Calculate g^a^b, i.e., Shared Key
            let sharedSecret = secp256k1.ecdh(pubKey: ephemPubKey, privateKey: data)
        else {
            throw SessionManagerError.runtimeError("ECDH Error")
        }
        let sharedSecretData = sharedSecret.data
        let sharedSecretPrefix = Array(tupleToArray(sharedSecretData).prefix(32))
        let reversedSharedSecret = sharedSecretPrefix.uint8Reverse()
        let hash = SHA2(variant: .sha512).calculate(for: Array(reversedSharedSecret))
        let aesEncryptionKey = Array(hash.prefix(32))
        let iv = opts.iv.hexa
        let macKey = Array(hash.suffix(32))
        var dataToMac: [UInt8] = opts.iv.hexa
        dataToMac.append(contentsOf: [UInt8](opts.ephemPublicKey.hexa))
        dataToMac.append(contentsOf: [UInt8](opts.ciphertext.hexa))
        do {
            let macGood = try? HMAC(key: macKey, variant: .sha2(.sha256)).authenticate(dataToMac)
            let macData = opts.mac.hexa
            if macGood != macData {
                throw SessionManagerError.runtimeError("Bad MAC error during decrypt")
            }
            // AES-CBCblock-256
            let aes = try AES(key: aesEncryptionKey, blockMode: CBC(iv: iv), padding: .pkcs7)
            let decrypt = try aes.decrypt(opts.ciphertext.hexa)
            let data = Data(decrypt)
            result = String(data: data, encoding: .utf8) ?? ""
        } catch let err {
            throw err
        }
        return result
    }
}
