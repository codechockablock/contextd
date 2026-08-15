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
//   * The key is generated with kSecAttrTokenIDSecureEnclave, so the private
//     key material never exists outside the Enclave and cannot be exported —
//     not by this process, not by anything running as the same UID.
//   * The access control is .biometryCurrentSet plus .userPresence with
//     kSecAccessControlPrivateKeyUsage, so EVERY signature needs a fresh
//     gesture. `LAContext` is created per invocation and never reused, which
//     is what makes "fresh" true rather than "once per session".
//   * Cancelling the prompt returns errSecUserCanceled; this helper exits
//     nonzero and writes nothing to stdout, so the caller appends nothing.
//   * It signs the bytes it is handed. It does not parse, interpret, or
//     reformat them — the payload is opaque here on purpose, because the
//     authority plane already decided exactly what would be signed.
//
// Build:  native/build.sh          (requires Xcode command line tools)
// This helper is NOT installed or enrolled by the build; both are operator
// actions. See docs/DEPLOYMENT.md.

import Foundation
import LocalAuthentication
import Security

let keyLabelPrefix = "com.contextd.operator."

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

func enroll(tag: String) {
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: Data((keyLabelPrefix + tag).utf8),
            kSecAttrAccessControl as String: accessControl(),
        ],
    ]
    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        fail("key generation failed: \(error!.takeRetainedValue())")
    }
    guard let publicKey = SecKeyCopyPublicKey(privateKey),
          let external = SecKeyCopyExternalRepresentation(publicKey, &error) as Data?
    else {
        fail("cannot export public key: \(error?.takeRetainedValue().localizedDescription ?? "unknown")")
    }
    // SecKeyCopyExternalRepresentation returns the raw X9.63 point (0x04 || X || Y).
    // Wrap it in a SubjectPublicKeyInfo so the registry stores a standard DER
    // key: the prefix below is the fixed ecPublicKey/prime256v1 header.
    let spkiHeader: [UInt8] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
        0x07, 0x03, 0x42, 0x00,
    ]
    var der = Data(spkiHeader)
    der.append(external)
    FileHandle.standardOutput.write(der)
}

func findKey(tag: String, context: LAContext) -> SecKey {
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrApplicationTag as String: Data((keyLabelPrefix + tag).utf8),
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecReturnRef as String: true,
        kSecUseAuthenticationContext as String: context,
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess, let key = item else {
        fail("no Secure Enclave key for tag \(tag) (OSStatus \(status))", code: 3)
    }
    return (key as! SecKey)
}

func sign(tag: String, summary: String) {
    // The payload is read whole and signed verbatim. It is opaque here.
    let message = FileHandle.standardInput.readDataToEndOfFile()
    guard !message.isEmpty else { fail("refusing to sign empty input", code: 2) }

    let reason = summary.isEmpty
        ? "Authorize a contextd operator action"
        : "Authorize: \(summary)"
    let context = freshContext(reason)
    let key = findKey(tag: tag, context: context)

    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(
        key,
        .ecdsaSignatureMessageX962SHA256,   // hashes the message itself
        message as CFData,
        &error
    ) as Data? else {
        let err = error!.takeRetainedValue()
        // errSecUserCanceled (-128) is the ordinary "operator said no" path.
        fail("signature refused or cancelled: \(err)", code: 4)
    }
    FileHandle.standardOutput.write(signature)
}

func list() {
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecReturnAttributes as String: true,
        kSecMatchLimit as String: kSecMatchLimitAll,
    ]
    var item: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
          let entries = item as? [[String: Any]] else {
        print("(no Secure Enclave keys)")
        return
    }
    for entry in entries {
        guard let tagData = entry[kSecAttrApplicationTag as String] as? Data,
              let tag = String(data: tagData, encoding: .utf8),
              tag.hasPrefix(keyLabelPrefix) else { continue }
        print(String(tag.dropFirst(keyLabelPrefix.count)))
    }
}

// --- argument handling ------------------------------------------------------

var arguments = Array(CommandLine.arguments.dropFirst())
guard let command = arguments.first else {
    fail("usage: contextd-signer (enroll|sign|list) [--key-id TAG] [--summary TEXT]")
}
arguments.removeFirst()

var tag = "default"
var summary = ""
var index = 0
while index < arguments.count {
    switch arguments[index] {
    case "--key-id":
        index += 1
        if index < arguments.count { tag = arguments[index] }
    case "--summary":
        index += 1
        if index < arguments.count { summary = arguments[index] }
    default:
        fail("unknown argument \(arguments[index])")
    }
    index += 1
}

switch command {
case "enroll": enroll(tag: tag)
case "sign":   sign(tag: tag, summary: summary)
case "list":   list()
default:       fail("unknown command \(command)")
}
