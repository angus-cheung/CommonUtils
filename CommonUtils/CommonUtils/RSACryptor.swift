import Foundation
import Security

 public class RSACrypto {

    public static func decrypt(publickeyStr: String, encrypted: String) throws -> [UInt8] {
       
        guard let encryptedData = encrypted.data(using: .utf8) else {
            throw NSError(domain: "Invalidencrypted", code: 0, userInfo: nil)
        }
        
        guard let encryptedBase64Data = Data(base64Encoded: encryptedData) else {
            throw NSError(domain: "InvalidencryptedData", code: 0, userInfo: nil)
        }
        
        guard let publicKey = try? getPublicKey(publickeyStr: publickeyStr) else {
            throw NSError(domain: "InvalidPublicKey", code: 0, userInfo: nil)
        }
        
        let buffer = [UInt8](encryptedBase64Data)
        var result = Data()
        
        var remain = buffer.count
        var off = 0
        
        while remain > 0 {
            let size = min(128, remain)
            let buf = Array(buffer[off..<off + size])
            
            if let out = try? rsaDecrypt(data: buf, publicKey: publicKey) {
                result.append(out)
            }
            
            remain -= size
            off += size
        }
        
        return [UInt8](result)
    }

    public static func getPublicKey(publickeyStr: String) throws -> SecKey {
        
        guard let publickeyStrData = publickeyStr.data(using: .utf8) else {
            throw NSError(domain: "InvalipublickeyStr", code: 0, userInfo: nil)
        }
        
        guard let data = Data(base64Encoded: publickeyStrData) else {
            throw NSError(domain: "InvalidpublickeyStrData", code: 0, userInfo: nil)
        }
        
        var error: Unmanaged<CFError>?
        
        guard let publicKey = SecKeyCreateWithData(data as CFData, [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic
        ] as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        
        return publicKey
    }

    public static func rsaDecrypt(data: [UInt8], publicKey: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        
        guard let decryptedData = SecKeyCreateDecryptedData(publicKey, .rsaEncryptionOAEPSHA512, Data(data) as CFData, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        
        return decryptedData
    }
}
