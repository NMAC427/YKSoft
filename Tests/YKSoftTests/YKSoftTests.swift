import XCTest

import libyksoft
@testable import YKSoft

final class YKSoftTests: XCTestCase {
    
    func testGenerateToken() {
        _ = YKToken.generate()
    }
    
    func testEncodeToken() throws {
        let token = YKToken.generate()
        let data = try JSONEncoder().encode(token)
        let decodedToken = try JSONDecoder().decode(YKToken.self, from: data)
        
        XCTAssertNotNil(decodedToken)
    }
    
    func testGenerateOTP() {
        XCTAssertNotNil(YKToken.generate().generateOTP())
    }
    
    func testMemorySafety() {
        for _ in 0..<10 {
            let token = YKToken.generate()
            
            print(token.privateID)
            print(token.publicID)
            print(token.aesKey)
            
            for _ in 0..<5 {
                print(token.generateOTP()!)
            }
        }
    }
}
