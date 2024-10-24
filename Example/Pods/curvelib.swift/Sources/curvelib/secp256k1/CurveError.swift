import Foundation

public struct CurveError: Error, LocalizedError {
    public enum ErrorType {
        case null
        case convert
        case parse
        case tweak
        case serialize
        case keySize
        case signature
        case invalidMac
        case encryption
        case decryption
        case unknownStatusCode
    }

    private(set) public var type: ErrorType

    public init(code: Int32) {
        switch code {
        case 1: type = .null
        case 2: type = .convert
        case 3: type = .parse
        case 4: type = .tweak
        case 5: type = .serialize
        case 6: type = .keySize
        case 7: type = .signature
        case 8: type = .invalidMac
        case 9: type = .encryption
        case 10: type = .decryption
        default: type = .unknownStatusCode
        }
    }

    public var errorDescription: String? {
        switch type {
        case .null:
            return "One or more of the parameters was null"
        case .convert:
            return "Invalid data was supplied"
        case .parse:
            return "Invalid data was supplied"
        case .tweak:
            return "Cannot perform tweak operation"
        case .serialize:
            return "Serialization failed"
        case .keySize:
            return "Incorrect key size"
        case .signature:
            return "Incorrect data supplied for signing or recovery"
        case .invalidMac:
            return "Invalid MAC"
        case .encryption:
            return "Unable to encrypt"
        case .decryption:
            return "Unable to decrypt"
        case .unknownStatusCode:
            return "Library reported an unknown status code, please open an issue on github"
        }
    }
}
