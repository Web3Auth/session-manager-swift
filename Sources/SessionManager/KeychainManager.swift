//
//  File.swift
//
//
//  Created by Dhruv Jaiswal on 18/07/22.
//

import KeychainSwift

public enum KeychainConstantEnum {
    case sessionID
    case custom(String)

    public var value: String {
        switch self {
        case .sessionID:
            return "sessionID"
        case let .custom(string):
            return string
        }
    }
}

protocol KeychainManagerProtocol {
    func get(key: KeychainConstantEnum) -> String?

    func delete(key: KeychainConstantEnum) -> Bool

    func save(key: KeychainConstantEnum, val: String) -> Bool
}

public class KeychainManager: KeychainManagerProtocol {
    public static let shared = KeychainManager()
    public var getAllKeys: [String] {
        return KeychainSwift().allKeys
    }

    private init() {}

    public func get(key: KeychainConstantEnum) -> String? {
        return KeychainSwift().get(key.value)
    }

    public func delete(key: KeychainConstantEnum) -> Bool {
        return KeychainSwift().delete(key.value)
    }

    public func save(key: KeychainConstantEnum, val: String) -> Bool {
        return KeychainSwift().set(val, forKey: key.value)
    }
}
