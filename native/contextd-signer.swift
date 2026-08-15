// contextd-signer — Secure Enclave P-256 signing with fresh user presence.
//
// This helper is the ONLY production path to an operator-authorized event.
// Everything it does is deliberately narrow:
//
//   enroll   create a non-exportable P-256 key in the Secure Enclave, gated on
//            user presence, and print its SubjectPublicKeyInfo as DER
//   sign     read the exact canonical bytes on stdin, request a presence
//            gesture, and write the DER (X9.62) ECDSA signature to stdout
//   list     print the key ids this device holds
//
// Properties this file is responsible for, per docs/adr/0001:
//
//   * The key is generated inside the Secure Enclave via CryptoKit
//     (SecureEnclave.P256). The private key material never exists outside the
//     Enclave and cannot be exported — not by this process, not by anything
//     running as the same UID. What this process holds is the key's
//     dataRepresentation: an Enclave-wrapped handle, ciphertext that only
//     THIS device's Enclave can use, stored 0600 under the operator's
//     Application Support. (The keychain-item storage this file first
//     shipped with requires keychain entitlements an ad-hoc binary cannot
//     carry — SecKeyCreateRandomKey fails with errSecMissingEntitlement
//     -34018 — and an entitlement-less keychain item would have been
//     same-UID readable anyway, so the handle file gives up nothing the
//     keychain route actually provided. The gate that matters is presence,
//     enforced by the Enclave itself, below.)
//   * The access control is .biometryCurrentSet OR .devicePasscode with
//     .privateKeyUsage, so EVERY signature needs an allowed presence gesture.
//     `LAContext` is created per invocation with reuse duration zero, which is
//     what makes "fresh" true rather than "once per session".
//   * Cancelling the prompt makes the signature throw; this helper exits
//     nonzero and writes nothing to stdout, so the caller appends nothing.
//   * It signs the bytes it is handed. It does not parse, interpret, or
//     reformat them — the payload is opaque here on purpose, because the
//     authority plane already decided exactly what would be signed.
//   * enroll refuses to overwrite an existing key id: replacing an enrolled
//     identity is `security key revoke` plus a fresh enrollment, never a
//     silent file clobber.
//
// Build:  native/build.sh          (requires Xcode command line tools)
// This helper is NOT installed or enrolled by the build; both are operator
// actions. See docs/DEPLOYMENT.md.

import Foundation
import CryptoKit
import LocalAuthentication
import Security

let keyLabelPrefix = "com.contextd.operator."
let keyFileSuffix = ".sekey"
let actionDomain = Data("contextd.OperatorActionV1\n".utf8)
let signerRequestDomain = Data("contextd.SignerRequestV1\n".utf8)

func fail(_ message: String, code: Int32 = 1) -> Never {
    FileHandle.standardError.write((message + "\n").data(using: .utf8)!)
    exit(code)
}

func accessControl() -> SecAccessControl {
    var error: Unmanaged<CFError>?
    guard let control = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        // .biometryCurrentSet invalidates the key if the enrolled biometric set
        // changes; .or .devicePasscode keeps the operator from being locked out
        // of their own archive by a fingerprint change.
        [.privateKeyUsage, .biometryCurrentSet, .or, .devicePasscode],
        &error
    ) else {
        fail("cannot build access control: \(error!.takeRetainedValue())")
    }
    return control
}

/// A brand-new LAContext per call. Reusing one would let a single gesture
/// authorize later signatures, which is exactly the property being bought.
func freshContext(_ reason: String) -> LAContext {
    let context = LAContext()
    context.localizedReason = reason
    context.touchIDAuthenticationAllowableReuseDuration = 0
    return context
}

/// The Enclave-wrapped key handles live here, one file per key id, in a
/// directory only this user can enter. The handles are device-bound
/// ciphertext; the directory modes are hygiene, not the security boundary.
func keyDirectory() -> URL {
    let base = FileManager.default.urls(
        for: .applicationSupportDirectory, in: .userDomainMask
    ).first!
    let dir = base.appendingPathComponent("contextd-signer", isDirectory: true)
    do {
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        // idempotent tighten: createDirectory attributes only apply on create
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700], ofItemAtPath: dir.path
        )
    } catch {
        fail("cannot prepare key directory \(dir.path): \(error)")
    }
    return dir
}

func keyFile(tag: String) -> URL {
    keyDirectory().appendingPathComponent(keyLabelPrefix + tag + keyFileSuffix)
}

func enroll(tag: String) {
    guard SecureEnclave.isAvailable else {
        fail("this device has no Secure Enclave; there is no software fallback")
    }
    let file = keyFile(tag: tag)
    if FileManager.default.fileExists(atPath: file.path) {
        fail(
            "a Secure Enclave key for tag \(tag) already exists; revoke and "
            + "remove it deliberately before enrolling a replacement",
            code: 5
        )
    }
    let key: SecureEnclave.P256.Signing.PrivateKey
    do {
        key = try SecureEnclave.P256.Signing.PrivateKey(
            accessControl: accessControl()
        )
    } catch {
        fail("key generation failed: \(error)")
    }
    do {
        try key.dataRepresentation.write(to: file, options: [.atomic])
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: file.path
        )
    } catch {
        try? FileManager.default.removeItem(at: file)
        fail("cannot store the wrapped key handle at \(file.path): \(error)")
    }
    // CryptoKit exposes the raw X9.63 point (0x04 || X || Y). Wrap it in a
    // SubjectPublicKeyInfo so the registry stores a standard DER key: the
    // prefix below is the fixed ecPublicKey/prime256v1 header.
    let spkiHeader: [UInt8] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
        0x07, 0x03, 0x42, 0x00,
    ]
    var der = Data(spkiHeader)
    der.append(key.publicKey.x963Representation)
    FileHandle.standardOutput.write(der)
}

func loadKey(tag: String, context: LAContext) -> SecureEnclave.P256.Signing.PrivateKey {
    let file = keyFile(tag: tag)
    guard let blob = try? Data(contentsOf: file) else {
        fail("no Secure Enclave key for tag \(tag) (expected \(file.path))", code: 3)
    }
    do {
        return try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: blob, authenticationContext: context
        )
    } catch {
        fail("cannot load Secure Enclave key for tag \(tag): \(error)", code: 3)
    }
}

enum CanonicalValue {
    case string(String)
    case integer(Int64)
    case list([CanonicalValue])
    case map([String: CanonicalValue])
}

struct CanonicalDecoder {
    let bytes: [UInt8]
    var offset: Int = 0

    mutating func take(_ count: Int) -> ArraySlice<UInt8> {
        guard count >= 0, offset <= bytes.count,
              count <= bytes.count - offset else {
            fail("malformed canonical action: truncated value", code: 2)
        }
        defer { offset += count }
        return bytes[offset..<(offset + count)]
    }

    mutating func uint64() -> UInt64 {
        let raw = take(8)
        return raw.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }

    mutating func boundedCount() -> Int {
        let value = uint64()
        guard value <= 4096, value <= UInt64(Int.max) else {
            fail("malformed canonical action: item bound exceeded", code: 2)
        }
        return Int(value)
    }

    mutating func stringValue(tagAlreadyRead: Bool = false) -> String {
        if !tagAlreadyRead {
            guard take(1).first == Character("s").asciiValue else {
                fail("malformed canonical action: map key is not text", code: 2)
            }
        }
        let length = boundedCount()
        guard let value = String(bytes: take(length), encoding: .utf8) else {
            fail("malformed canonical action: invalid UTF-8", code: 2)
        }
        return value
    }

    mutating func value(depth: Int = 0) -> CanonicalValue {
        guard depth <= 8, let tag = take(1).first else {
            fail("malformed canonical action: depth bound exceeded", code: 2)
        }
        switch tag {
        case Character("s").asciiValue:
            return .string(stringValue(tagAlreadyRead: true))
        case Character("i").asciiValue:
            let bits = take(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
            return .integer(Int64(bitPattern: bits))
        case Character("l").asciiValue:
            let count = boundedCount()
            return .list((0..<count).map { _ in value(depth: depth + 1) })
        case Character("m").asciiValue:
            let count = boundedCount()
            var result: [String: CanonicalValue] = [:]
            var previous: [UInt8]? = nil
            for _ in 0..<count {
                let key = stringValue()
                let keyBytes = Array(key.utf8)
                if let prior = previous, !prior.lexicographicallyPrecedes(keyBytes) {
                    fail("malformed canonical action: map keys not canonical", code: 2)
                }
                guard result[key] == nil else {
                    fail("malformed canonical action: duplicate map key", code: 2)
                }
                previous = keyBytes
                result[key] = value(depth: depth + 1)
            }
            return .map(result)
        default:
            fail("malformed canonical action: unknown type tag", code: 2)
        }
    }
}

func hexDigest(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

func preview(_ value: String) -> String {
    let escaped = value
        .replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "\n", with: "\\n")
        .replacingOccurrences(of: "\r", with: "\\r")
        .replacingOccurrences(of: "\t", with: "\\t")
    return String(escaped.prefix(240))
}

func trustedSummary(_ message: Data, content: String, reason: String) -> String {
    guard message.starts(with: actionDomain) else {
        fail("refusing a payload outside OperatorActionV1", code: 2)
    }
    var decoder = CanonicalDecoder(
        bytes: Array(message.dropFirst(actionDomain.count))
    )
    guard case let .map(action) = decoder.value(),
          decoder.offset == decoder.bytes.count else {
        fail("malformed canonical operator action", code: 2)
    }
    let expected: Set<String> = [
        "domain", "version", "archive_uuid", "key_id", "nonce", "sequence",
        "issued_at", "expires_at", "action", "scope", "arguments",
        "content_digest", "reason_digest",
    ]
    guard Set(action.keys) == expected,
          case let .string(domain)? = action["domain"],
          domain == "contextd.OperatorActionV1",
          case let .integer(version)? = action["version"], version == 1,
          case let .string(operation)? = action["action"],
          case let .string(scope)? = action["scope"],
          case let .integer(sequence)? = action["sequence"],
          case let .integer(expiresAt)? = action["expires_at"],
          case let .string(contentDigest)? = action["content_digest"],
          case let .string(reasonDigest)? = action["reason_digest"],
          case let .map(arguments)? = action["arguments"] else {
        fail("malformed OperatorActionV1 fields", code: 2)
    }
    let allowedActions: Set<String> = [
        "note.deliberate", "loop.add", "loop.confirm", "loop.close",
        "loop.reopen", "loop.dismiss", "grant.add", "grant.revoke",
        "decision.supersede", "archive.raw_read",
        "archive.export", "archive.backup", "archive.restore",
        "security.key_register", "security.key_revoke",
    ]
    guard allowedActions.contains(operation), sequence > 0 else {
        fail("unknown or invalid operator action", code: 2)
    }
    guard hexDigest(Data(content.utf8)) == contentDigest,
          hexDigest(Data(reason.utf8)) == reasonDigest else {
        fail(
            "trusted display text does not match the signed content/reason digest",
            code: 2
        )
    }
    let argumentSummary = arguments.keys.sorted().map { key -> String in
        switch arguments[key]! {
        case let .string(value): return "\(key)=\(String(value.prefix(80)))"
        case let .integer(value): return "\(key)=\(value)"
        default: fail("operator action argument is not scalar", code: 2)
        }
    }.joined(separator: ", ")
    let expiry = Date(timeIntervalSince1970: TimeInterval(expiresAt))
    let formatter = ISO8601DateFormatter()
    let digest = hexDigest(message)
    return "Authorize \(operation) on \(String(scope.prefix(160))); "
        + (argumentSummary.isEmpty ? "" : "\(argumentSummary); ")
        + (content.isEmpty ? "" : "content ‘\(preview(content))’; ")
        + (reason.isEmpty ? "" : "reason ‘\(preview(reason))’; ")
        + "sequence \(sequence); expires \(formatter.string(from: expiry)); "
        + "digest \(digest.prefix(16))"
}

func signerRequest(_ request: Data) -> (Data, String, String) {
    guard request.starts(with: signerRequestDomain) else {
        fail("malformed signer request domain", code: 2)
    }
    let bytes = [UInt8](request)
    var offset = signerRequestDomain.count

    func field(_ label: String, max: Int) -> Data {
        guard offset + 8 <= bytes.count else {
            fail("malformed signer request: missing \(label) length", code: 2)
        }
        let length = bytes[offset..<(offset + 8)].reduce(UInt64(0)) {
            ($0 << 8) | UInt64($1)
        }
        offset += 8
        guard length <= UInt64(max), length <= UInt64(bytes.count - offset) else {
            fail("malformed signer request: \(label) exceeds its bound", code: 2)
        }
        let end = offset + Int(length)
        defer { offset = end }
        return Data(bytes[offset..<end])
    }

    let canonical = field("canonical action", max: 128 * 1024)
    let contentData = field("display content", max: 128 * 1024)
    let reasonData = field("display reason", max: 8 * 1024)
    guard offset == bytes.count,
          let content = String(data: contentData, encoding: .utf8),
          let reason = String(data: reasonData, encoding: .utf8) else {
        fail("malformed signer request: trailing bytes or invalid UTF-8", code: 2)
    }
    return (canonical, content, reason)
}

func sign(tag: String) {
    let request = FileHandle.standardInput.readDataToEndOfFile()
    guard !request.isEmpty else { fail("refusing to sign empty input", code: 2) }
    let (message, content, displayReason) = signerRequest(request)

    let reason = trustedSummary(message, content: content, reason: displayReason)
    let context = freshContext(reason)
    let key = loadKey(tag: tag, context: context)

    // SHA-256 of the message, signed inside the Enclave: byte-identical to
    // the SecKey .ecdsaSignatureMessageX962SHA256 signatures this helper
    // produced before, and verified the same way by the registry.
    let signature: P256.Signing.ECDSASignature
    do {
        signature = try key.signature(for: SHA256.hash(data: message))
    } catch {
        // The operator cancelling the presence prompt lands here; that is the
        // ordinary "operator said no" path.
        fail("signature refused or cancelled: \(error)", code: 4)
    }
    FileHandle.standardOutput.write(signature.derRepresentation)
}

func list() {
    let contents = (try? FileManager.default.contentsOfDirectory(
        at: keyDirectory(), includingPropertiesForKeys: nil
    )) ?? []
    let tags = contents.compactMap { url -> String? in
        let name = url.lastPathComponent
        guard name.hasPrefix(keyLabelPrefix), name.hasSuffix(keyFileSuffix)
        else { return nil }
        return String(name.dropFirst(keyLabelPrefix.count)
                          .dropLast(keyFileSuffix.count))
    }.sorted()
    if tags.isEmpty {
        print("(no Secure Enclave keys)")
        return
    }
    for tag in tags { print(tag) }
}

// --- argument handling ------------------------------------------------------

var arguments = Array(CommandLine.arguments.dropFirst())
guard let command = arguments.first else {
    fail("usage: contextd-signer (enroll|sign|list) [--key-id TAG]")
}
arguments.removeFirst()

var tag = "default"
var index = 0
while index < arguments.count {
    switch arguments[index] {
    case "--key-id":
        index += 1
        if index < arguments.count { tag = arguments[index] }
    default:
        fail("unknown argument \(arguments[index])")
    }
    index += 1
}

let allowedTag = CharacterSet(
    charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
)
guard !tag.isEmpty, tag.count <= 64,
      tag.unicodeScalars.allSatisfy({ allowedTag.contains($0) }) else {
    fail("key tag must be 1-64 ASCII letters, digits, dot, underscore, or dash")
}

switch command {
case "enroll": enroll(tag: tag)
case "sign":   sign(tag: tag)
case "list":   list()
default:       fail("unknown command \(command)")
}
