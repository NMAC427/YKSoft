import Foundation
import libyksoft

class YKToken: Codable, CustomStringConvertible {
    private var token: yk_token_t
    
    private(set) lazy var publicID: String = {
        return cStringToString(ptr: yk_token_public_id(&self.token))!
    }()
    private(set) lazy var privateID: String = {
        return cStringToString(ptr: yk_token_private_id(&self.token))!
    }()
    private(set) lazy var aesKey: String = {
        return cStringToString(ptr: yk_token_aes_key(&self.token))!
    }()
    
    init(token: yk_token_t) {
        self.token = token
    }
    
    required init(from decoder: Decoder) throws {
        var tokenData = try decoder.singleValueContainer().decode(Data.self)
        self.token = tokenData.withUnsafeMutableBytes { bytes in
            bytes.assumingMemoryBound(to: yk_token_t.self).first!
        }
    }
    
    func encode(to encoder: Encoder) throws {
        let tokenData = withUnsafeMutableBytes(of: &self.token) { bytes in
            Data(buffer: bytes.assumingMemoryBound(to: yk_token_t.self))
        }
        
        var container = encoder.singleValueContainer()
        try container.encode(tokenData)
    }
    
    var description: String {
        return "YKToken[" + String(describing: self.token) + "]"
    }
    
    static func generate() -> YKToken {
        let newToken = yk_generate_new_token()
        return YKToken(token: newToken)
    }
    
    func generateOTP() -> String? {
        return cStringToString(ptr: yk_generate_otp(&self.token))
    }
}


private func cStringToString(ptr: UnsafeMutablePointer<CChar>?) -> String? {
    guard let ptr = ptr else {
        return nil
    }
    
    let string = String(cString: ptr)
    free(ptr)
    
    return string
}
