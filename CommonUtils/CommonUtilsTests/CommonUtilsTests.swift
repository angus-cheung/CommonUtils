//
//  CommonUtilsTests.swift
//  CommonUtilsTests
//
//  Created by Zhang Zhang on 2024/2/15.
//

import XCTest
import CommonCrypto
@testable import CommonUtils



final class CommonUtilsTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testExample() throws {
        do {
            let plaintext = "Hello, World!".data(using: .utf8)!
            let key128 = "1234567890123456".data(using: .utf8)!
            let key256 = "12345678901234561234567890123456".data(using: .utf8)!
            let iv = "abcdefghijklmnop".data(using: .utf8)!

            let encryptedData128 = try AESCryptor.encrypt(data: plaintext, key: key128, iv: iv, keySize: kCCKeySizeAES128)
            let decryptedData128 = try AESCryptor.decrypt(data: encryptedData128, key: key128, iv: iv, keySize: kCCKeySizeAES128)

            let encryptedData256 = try AESCryptor.encrypt(data: plaintext, key: key256, iv: iv, keySize: kCCKeySizeAES256)
            let decryptedData256 = try AESCryptor.decrypt(data: encryptedData256, key: key256, iv: iv, keySize: kCCKeySizeAES256)

            let encryptedString128 = encryptedData128.base64EncodedString()
            let decryptedString128 = String(data: decryptedData128, encoding: .utf8)!

            let encryptedString256 = encryptedData256.base64EncodedString()
            let decryptedString256 = String(data: decryptedData256, encoding: .utf8)!

            print("Original: \(plaintext)")
            print("Encrypted (AES-128): \(encryptedString128)")
            print("Decrypted (AES-128): \(decryptedString128)")

            print("Encrypted (AES-256): \(encryptedString256)")
            print("Decrypted (AES-256): \(decryptedString256)")
        } catch {
            print("Error: \(error)")
        }
    }

    func testDecryptWithValidInput() {
        
        let publicKey = "MEgCQQCo9+BpMRYQ/dL3DS2CyJxRF+j6ctbT3/Qp84+KeFhnii7NT7fELilKUSnxS30WAvQCCo2yU1orfgqr41mM70MBAgMBAAE="
        let encryptedData = "odKAmV6AbsoWsyL3thUoYVDEJAsQl8RrH+JuQ9HWUnDLunDdLEM6oNl15XP1xLOHz3bEq1rvATiQmAByKNOiVujd1gsq7JxfQYDdHRzDhZZrUstnetvGTDBtMHmhzbBXOih+1q3eA2RMQ5izXOEkyMKrWWlcKMWVJzMSYjFeFJB8D8wJNmq1ArNCO3uXfwkZuMnMhYhx/OYvCs4sMWKe5/etyR2gz0Fvp6VDUa0jNRvoad+8/pHK7KDxB8nW5KgmpSjfkl1Ut3zChtwEuAFnSDuypbrODBdphZHD40WmX0f69VKKs44vsKCHr8nzJ8R5dw+2Ggyq5W5hl3PDTMTqn8Pc+cwmPdVe4bkNqxbCHe2omZXpNIgC31wrMBvkyUYvpY8rMoBXqgm9hC5JsXzn6Z6X1kpGFhDjkNSdzx4jYzw="
        
        // 使用上述 publicKey 和 encryptedData 進行解密測試
        do {
            let decryptedData = try RSACrypto.decrypt(publickeyStr: publicKey, encrypted: encryptedData)
            XCTAssertNotNil(decryptedData, "Decryption should succeed with valid input")
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
    
}
