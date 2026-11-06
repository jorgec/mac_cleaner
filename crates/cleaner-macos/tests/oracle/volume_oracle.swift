// Swift oracle for ADR 0002: prints the four Foundation volume capacity values for a path as one
// line `<total> <available> <important> <opportunistic>` (bytes, `-1` when Foundation returns nil).
// Used only by the opt-in test `ac_002_3_volume_adapter_agrees_with_the_swift_oracle`
// (`#[ignore = "requires-swift-oracle"]`). Read-only; run as `swift volume_oracle.swift <path>`.
import Foundation

let path = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "/"
let url = URL(fileURLWithPath: path)
let keys: Set<URLResourceKey> = [
    .volumeTotalCapacityKey,
    .volumeAvailableCapacityKey,
    .volumeAvailableCapacityForImportantUsageKey,
    .volumeAvailableCapacityForOpportunisticUsageKey,
]
do {
    let v = try url.resourceValues(forKeys: keys)
    let total = v.volumeTotalCapacity.map { Int64($0) } ?? -1
    let available = v.volumeAvailableCapacity.map { Int64($0) } ?? -1
    let important = v.volumeAvailableCapacityForImportantUsage ?? -1
    let opportunistic = v.volumeAvailableCapacityForOpportunisticUsage ?? -1
    print(total, available, important, opportunistic)
} catch {
    FileHandle.standardError.write(Data("oracle failed: \(error)\n".utf8))
    exit(1)
}
