// Used only on hosts with Command Line Tools but no Xcode/XCTest. CI uses real XCTest.
import Foundation
class XCTestCase {}
let failureLock = NSLock()
var failures: [String] = []
func XCTFail(_ message: String = "Failure", file: StaticString = #filePath, line: UInt = #line) {
    failureLock.lock(); failures.append("\(file):\(line): \(message)"); failureLock.unlock()
}
func XCTAssertTrue(_ value: @autoclosure () throws -> Bool, file: StaticString = #filePath, line: UInt = #line) {
    do { if try !value() { XCTFail("Expected true", file: file, line: line) } } catch { XCTFail("Unexpected error: \(error)", file: file, line: line) }
}
func XCTAssertFalse(_ value: @autoclosure () throws -> Bool, file: StaticString = #filePath, line: UInt = #line) {
    do { if try value() { XCTFail("Expected false", file: file, line: line) } } catch { XCTFail("Unexpected error: \(error)", file: file, line: line) }
}
func XCTAssertEqual<T: Equatable>(_ a: @autoclosure () throws -> T, _ b: @autoclosure () throws -> T, file: StaticString = #filePath, line: UInt = #line) {
    do { let x = try a(), y = try b(); if x != y { XCTFail("\(x) != \(y)", file: file, line: line) } } catch { XCTFail("Unexpected error: \(error)", file: file, line: line) }
}
func XCTAssertNotEqual<T: Equatable>(_ a: @autoclosure () throws -> T, _ b: @autoclosure () throws -> T, file: StaticString = #filePath, line: UInt = #line) {
    do { let x = try a(), y = try b(); if x == y { XCTFail("Values unexpectedly equal", file: file, line: line) } } catch { XCTFail("Unexpected error: \(error)", file: file, line: line) }
}
func XCTAssertThrowsError<T>(_ action: @autoclosure () throws -> T, file: StaticString = #filePath, line: UInt = #line) {
    do { _ = try action(); XCTFail("Expected an error", file: file, line: line) } catch {}
}
