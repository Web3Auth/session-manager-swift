import Foundation

/**
 List of possible web-based authentication errors.
 */
public enum SessionManagerError: Error {
    case runtimeError(String)
    case decodingError
    case encodingError
    case sessionIDAbsent
}

extension SessionManagerError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case let .runtimeError(msg):
            return msg
        case .decodingError:
            return "Decoding error"
        case .encodingError:
            return "Encoding error"
        case .sessionIDAbsent:
            return "SessionID not found!"
        }
    }
}
