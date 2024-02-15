//
//  AESCryptor.swift
//  CommonUtils
//
//  Created by Zhang Zhang on 2024/2/15.
//

import Foundation

import CommonCrypto

public enum CryptoError: Error {
    case encryptionFailed
    case decryptionFailed
    case invalidKeyLength
}

public class AESCryptor {
    public static func encrypt(data: Data, key: Data, iv: Data, keySize: Int) throws -> Data {
        guard keySize == kCCKeySizeAES128 || keySize == kCCKeySizeAES256 else {
            throw CryptoError.invalidKeyLength
        }

        var encryptedData = Data(count: data.count + kCCBlockSizeAES128)
        var encryptedDataLength: Int = 0

        let status = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                data.withUnsafeBytes { dataBytes in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyBytes.baseAddress, keySize,
                        ivBytes.baseAddress,
                        dataBytes.baseAddress, data.count,
                        encryptedData.withUnsafeMutableBytes { $0.baseAddress }, encryptedData.count,
                        &encryptedDataLength
                    )
                }
            }
        }

        guard status == kCCSuccess else {
            throw CryptoError.encryptionFailed
        }

        encryptedData.removeSubrange(encryptedDataLength..<encryptedData.count)

        return encryptedData
    }

    public static func decrypt(data: Data, key: Data, iv: Data, keySize: Int) throws -> Data {
        guard keySize == kCCKeySizeAES128 || keySize == kCCKeySizeAES256 else {
            throw CryptoError.invalidKeyLength
        }

        var decryptedData = Data(count: data.count + kCCBlockSizeAES128)
        var decryptedDataLength: Int = 0

        let status = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                data.withUnsafeBytes { dataBytes in
                    CCCrypt(
                        CCOperation(kCCDecrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyBytes.baseAddress, keySize,
                        ivBytes.baseAddress,
                        dataBytes.baseAddress, data.count,
                        decryptedData.withUnsafeMutableBytes { $0.baseAddress }, decryptedData.count,
                        &decryptedDataLength
                    )
                }
            }
        }

        guard status == kCCSuccess else {
            throw CryptoError.decryptionFailed
        }

        decryptedData.removeSubrange(decryptedDataLength..<decryptedData.count)

        return decryptedData
    }
}
