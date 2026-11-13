// Stub replacement for NXBuilder (removed MDK/LLVM dependency)
import Foundation

final class NXBuilder: NSObject {
    static var builds: Bool { return false }
    private(set) var project: Any?
    
    init(project: Any) {
        self.project = project
        super.init()
    }
    
    func build() throws {
        // no-op: device-side compilation removed for lightweight build
    }
}
