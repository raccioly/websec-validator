// Authored source-only coverage control, not the unavailable original V9 application.
import Foundation
let untrustedName = CommandLine.arguments[1]
let process = Process()
process.executableURL = URL(fileURLWithPath: "/bin/sh")
process.arguments = ["-c", "tar czf /tmp/out.tgz \(untrustedName)"]
try process.run()
