# Security Policy

## Security Status

ECI2 is experimental security software implementing an application-specific hybrid public-key encryption protocol.

ECI2 combines:

* X25519
* ML-KEM-768
* HKDF-SHA-384
* AES-256-GCM

The underlying cryptographic primitives are established algorithms, but **ECI2 itself is not a standardized encryption protocol**.

The composition, binary format, key-container format, and implementation are project-specific.

Accordingly, ECI2 should not be considered suitable for high-assurance, safety-critical, or otherwise high-value deployments without independent security review.

---

## Supported Versions

Security fixes are normally applied only to the current development version.

| Version                      | Supported   |
| ---------------------------- | ----------- |
| Current release              | Yes         |
| Previous releases            | Best effort |
| ECI1 / legacy implementation | No          |

ECI1 is a separate, classical-only protocol and is not considered a supported post-quantum security mechanism.

Security fixes may require a new protocol version or cryptographic-suite identifier when changing protocol behavior would otherwise create compatibility or downgrade concerns.

---

# Reporting a Security Vulnerability

Please **do not report security vulnerabilities through public GitHub Issues**.

Security-sensitive reports should be submitted privately through GitHub's **Private Vulnerability Reporting** mechanism if it is enabled for this repository.

If Private Vulnerability Reporting is not available, contact the repository maintainers through the security contact specified in the repository's GitHub metadata.

When possible, provide:

* A concise description of the vulnerability.
* The affected version or commit.
* The affected component or function.
* Steps required to reproduce the issue.
* A minimal proof of concept, where appropriate.
* Expected behavior.
* Actual behavior.
* Security impact.
* Any known prerequisites or environmental requirements.
* Suggested remediation, if known.

Please avoid including actual confidential data, private keys, credentials, or other sensitive information in the report.

---

# What Should Be Reported Privately?

Examples include:

* Cryptographic weaknesses.
* Incorrect use of cryptographic primitives.
* Incorrect key derivation.
* Weak or predictable randomness.
* AES-GCM nonce-reuse vulnerabilities.
* Authentication bypasses.
* Failures to authenticate ECI2 package headers.
* Package parsing vulnerabilities with security consequences.
* Key-material disclosure.
* Private-key exposure.
* ML-KEM or X25519 misuse.
* Protocol downgrade vulnerabilities.
* Algorithm-confusion vulnerabilities.
* Parser vulnerabilities that can result in arbitrary code execution.
* Memory-safety issues with security impact.
* Authentication-tag bypasses.
* Vulnerabilities allowing plaintext recovery without the recipient private key.
* Vulnerabilities allowing unauthorized modification of authenticated ciphertext.
* Vulnerabilities that undermine the intended hybrid post-quantum security properties.

When uncertain whether an issue has security implications, **report it privately**.

---

# What Should Be Reported as a Normal Issue?

Ordinary bugs that do not create a security vulnerability can be reported through GitHub Issues.

Examples include:

* Documentation errors.
* CLI usability problems.
* Non-security-related exceptions.
* Portability problems without security consequences.
* Test failures unrelated to security.
* Feature requests.
* Performance improvements.
* Non-security-related code-quality issues.

If a normal issue later appears to have security implications, do not continue discussing exploit details publicly. Contact the maintainers privately.

---

# Vulnerability Disclosure Process

The maintainers will attempt to:

1. Acknowledge receipt of a security report.
2. Reproduce and assess the reported issue.
3. Determine affected versions and security impact.
4. Develop and test an appropriate remediation.
5. Determine whether a protocol-version or cryptographic-suite change is required.
6. Prepare an advisory when appropriate.
7. Release the remediation.
8. Publicly disclose relevant details after affected users have had a reasonable opportunity to update.

The precise timeline may depend upon the severity and complexity of the vulnerability.

---

# Coordinated Disclosure

Please allow reasonable time for investigation and remediation before publicly disclosing a vulnerability.

For serious cryptographic or protocol vulnerabilities, premature disclosure may expose users to avoidable risk because encrypted material may remain vulnerable even after the software itself has been patched.

The maintainers may request coordinated disclosure of:

* The vulnerability description.
* Affected versions.
* Remediation.
* Detection guidance.
* Migration requirements.
* Protocol changes.

---

# Cryptographic Vulnerabilities

Cryptographic vulnerabilities receive special consideration.

A report involving the security assumptions of X25519, ML-KEM-768, HKDF, or AES-256-GCM should clearly distinguish between:

1. A weakness in the underlying standardized algorithm.
2. Incorrect use of the algorithm by ECI2.
3. A weakness in the ECI2 hybrid construction.
4. An implementation defect.

For example, a hypothetical attack against X25519 does not necessarily demonstrate a weakness in ECI2 if ML-KEM-768 remains secure and is correctly incorporated into the key derivation.

Conversely, an implementation that accidentally derives the AES key solely from the X25519 shared secret would be a serious ECI2 vulnerability even if X25519 itself remains secure.

---

# Hybrid Security Expectations

ECI2 is intended to derive the AES encryption key from both:

```text
X25519 shared secret
+
ML-KEM-768 shared secret
```

through the specified HKDF construction.

A security issue that allows an attacker to eliminate either component from the derived key should be treated as potentially significant.

Particular attention should be given to vulnerabilities involving:

* Secret concatenation.
* KDF domain separation.
* Algorithm identifiers.
* Protocol version handling.
* KEM decapsulation.
* Ephemeral-key handling.
* Recipient-key substitution.
* Header authentication.
* Cryptographic-suite confusion.
* Downgrade behavior.

---

# AES-GCM Nonce Security

AES-GCM requires appropriate nonce management.

The implementation currently generates a fresh 96-bit nonce for each package.

Reports demonstrating deterministic nonce reuse, nonce reuse caused by concurrency, predictable nonces, or other conditions that materially increase the probability of nonce collision should be treated as security-sensitive.

Do not publicly publish working demonstrations that facilitate practical exploitation of nonce-reuse conditions before coordinating with the maintainers.

---

# Key Material

ECI2 private-key files contain sensitive cryptographic material.

A vulnerability that exposes:

* X25519 private keys,
* ML-KEM private seeds,
* decrypted plaintext,
* derived AES keys,

or equivalent secrets should be reported privately.

Do not submit real private keys or confidential plaintext as part of a public issue or pull request.

Use synthetic test keys and test data when reproducing security problems.

---

# Package Parsing

ECI2 packages are attacker-controlled input whenever encrypted packages can be received from untrusted sources.

Security reports concerning malformed packages should therefore consider whether the issue can result in:

* Process crashes.
* Excessive memory consumption.
* Excessive CPU consumption.
* Authentication bypass.
* Plaintext disclosure.
* Out-of-bounds access.
* Denial of service.
* Unexpected filesystem access.
* Code execution.

Simple rejection of an invalid package is normally expected behavior and is not itself a vulnerability.

---

# Denial of Service

ECI2 accepts potentially untrusted package data.

Resource-exhaustion vulnerabilities should be reported privately when an attacker can cause disproportionate:

* memory allocation,
* CPU consumption,
* disk consumption,
* cryptographic computation,
* process termination,

particularly if the attack can be performed remotely or repeatedly.

The current implementation has an approximately 1 GiB package/plaintext limit, but this should not be interpreted as complete protection against denial-of-service attacks.

---

# Side Channels

The project attempts to rely on cryptographic implementations provided by the `cryptography` package rather than implementing low-level cryptographic primitives.

Potential side-channel vulnerabilities should nevertheless be reported privately.

Examples include:

* Timing differences exposing secret information.
* Secret-dependent error behavior.
* Secret-dependent memory behavior.
* Cache-based leakage.
* Differences in cryptographic failure handling that expose key material.

The maintainers will distinguish vulnerabilities in ECI2 from vulnerabilities in the underlying cryptographic library or platform.

---

# Supply-Chain Security

The project depends on the `cryptography` package for its cryptographic primitives.

Users should obtain dependencies from trusted package repositories and should use appropriate dependency-management controls for production deployments.

Security issues involving:

* malicious dependencies,
* compromised package releases,
* dependency confusion,
* dependency substitution,
* compromised build artifacts,

should be reported when they affect this project's distribution or recommended installation process.

The project does not claim to provide an independently verified cryptographic implementation of X25519, ML-KEM, HKDF, or AES-GCM.

---

# Private-Key Protection

ECI2 currently stores private-key material in an unencrypted local key container.

File-system permissions provide only limited protection.

A compromise of the ECI2 private-key file should be considered a compromise of the corresponding recipient key.

This is a known design limitation rather than an assumed security boundary.

Future releases may provide encrypted private-key storage.

---

# Sender Authentication

ECI2 encryption does **not** authenticate the sender.

A successful decryption does not establish that a particular person, organization, or system created the package.

Do not report the absence of sender authentication as a vulnerability unless the application or a documented protocol extension explicitly claims to provide it.

Applications requiring sender authentication should use an appropriate digital-signature mechanism, such as a standardized post-quantum signature scheme, in addition to encryption.

---

# Forward Secrecy

ECI2 uses an ephemeral X25519 key for each encryption operation.

However, ECI2 is a file/message encryption format rather than an interactive key-exchange protocol.

The project therefore does not make broad claims of formal forward secrecy.

Reports demonstrating recovery of historical plaintext following compromise of long-term recipient key material should be evaluated against the documented ECI2 threat model rather than assumed to violate a forward-secrecy guarantee that the protocol does not claim.

---

# Security Advisories

Confirmed security vulnerabilities may result in a GitHub Security Advisory.

Depending on severity, remediation may include:

* A software patch.
* A dependency update.
* A new ECI2 protocol version.
* A new cryptographic-suite identifier.
* Key rotation.
* Re-encryption of existing data.
* Migration away from an affected protocol version.
* Changes to key-management procedures.

Protocol-level vulnerabilities may require migration of previously encrypted data.

---

# Severity Considerations

Severity will be assessed based on practical exploitability and impact.

Particular weight will be given to vulnerabilities that permit:

### Critical

* Plaintext recovery without the recipient's private key.
* Recovery of long-term private keys.
* Forgery of authenticated ciphertext.
* Practical compromise of the hybrid KEM construction.
* Remote arbitrary code execution.

### High

* Reliable denial of service against untrusted package processing.
* Significant cryptographic downgrade.
* Key compromise under realistic conditions.
* Authentication bypass.
* Practical exposure of sensitive cryptographic material.

### Medium

* Limited information disclosure.
* Restricted denial of service.
* Security-boundary violations requiring substantial prerequisites.
* Issues affecting unusual configurations.

### Low

* Issues with limited practical security impact.
* Defense-in-depth weaknesses.
* Information disclosures that do not expose sensitive cryptographic material.

Severity classifications are guidelines rather than guarantees.

---

# Reporting Vulnerabilities in Dependencies

If a vulnerability exists solely in a third-party dependency, report it to the appropriate upstream project as well.

If the dependency vulnerability has a direct impact on ECI2 users, also notify this project's maintainers so that:

* affected versions can be identified,
* dependency constraints can be updated,
* mitigation guidance can be documented.

---

# Responsible Research

Security research against ECI2 is welcome.

Researchers should:

* Use synthetic keys and test data.
* Avoid accessing data that does not belong to them.
* Avoid disrupting systems or services.
* Avoid destructive testing against third-party infrastructure.
* Avoid publicly disclosing working exploits before coordinated remediation.
* Preserve enough technical detail for maintainers to reproduce the issue.

Testing the local command-line utility against deliberately malformed packages is encouraged.

---

# Cryptographic Design Changes

Changes to cryptographic behavior require additional scrutiny.

Pull requests that modify any of the following should not be treated as ordinary refactoring:

* KDF inputs.
* KDF salt handling.
* KDF domain separation.
* Cryptographic algorithms.
* Key sizes.
* Nonce generation.
* AEAD construction.
* ML-KEM parameters.
* X25519 handling.
* Package authentication.
* Protocol versioning.
* Cryptographic-suite identifiers.
* Key serialization.
* Private-key storage.

Such changes should document:

1. The security rationale.
2. The affected threat model.
3. Compatibility implications.
4. Migration implications.
5. Any relevant cryptographic references.
6. New or modified security tests.

---

# Security Testing Expectations

Security-sensitive changes should include tests demonstrating both the intended operation and failure behavior.

At minimum, relevant tests should cover:

```text
valid package
    -> decrypts successfully

modified ciphertext
    -> authentication failure

modified header
    -> authentication failure

modified X25519 ephemeral key
    -> authentication failure

modified ML-KEM ciphertext
    -> authentication failure

modified salt
    -> authentication failure

modified nonce
    -> authentication failure

modified ciphertext length
    -> package rejection

truncated package
    -> package rejection

unexpected trailing data
    -> package rejection

wrong private key
    -> authentication/decryption failure

unsupported suite
    -> package rejection

unsupported version
    -> package rejection
```

Tests should never use real production keys or sensitive data.

---

# Contact

Security reports should be submitted through the repository's configured private security-reporting mechanism.

If GitHub Private Vulnerability Reporting is enabled, use:

**GitHub → Security → Advisories → Report a vulnerability**

Do not use public GitHub Issues for undisclosed vulnerabilities.

---

# Acknowledgements

Security researchers who responsibly report confirmed vulnerabilities may be acknowledged in the relevant security advisory, unless they request otherwise.

No researcher should assume that public attribution will occur automatically.

---

# Disclaimer

ECI2 is experimental cryptographic software.

The project does not guarantee that ECI2 is secure against all known or future attacks.

In particular, the use of standardized cryptographic primitives does not establish that the overall ECI2 protocol has received formal cryptographic analysis or independent security review.

Users requiring high assurance should obtain independent review of the protocol, implementation, deployment architecture, and key-management procedures before relying on ECI2 to protect sensitive information.
