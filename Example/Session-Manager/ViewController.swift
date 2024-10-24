//
//  ViewController.swift
//  Session-Manager
//
//  Created by dhruv@tor.us on 04/12/2023.
//  Copyright (c) 2023 dhruv@tor.us. All rights reserved.
//

import UIKit
import SessionManager
import curveSecp256k1

class ViewController: UIViewController {
    struct SFAModel: Codable {
        let publicKey: String
        let privateKey: String
    }
    
    var session: SessionManager!

    private func generatePrivateandPublicKey() throws -> (privKey: String, pubKey: String) {
        let privKeyData = curveSecp256k1.SecretKey()
        let publicKey = try privKeyData.toPublic()
        let serialized = try publicKey.serialize(compressed: false)
        return (privKey: try privKeyData.serialize(), pubKey: serialized)
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        Task {
            let sessionId = try SessionManager.generateRandomSessionID()!;
            session = SessionManager(sessionId: sessionId)
            let (privKey, pubKey) = try generatePrivateandPublicKey()
            let sfa = SFAModel(publicKey: pubKey, privateKey: privKey)
            let created = try await session.createSession(data: sfa)
            SessionManager.saveSessionIdToStorage(sessionId)
                    let auth = try await session.authorizeSession(origin: "")
            print(created)
        }
        // Do any additional setup after loading the view, typically from a nib.
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

}
