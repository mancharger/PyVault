# PyVault Specification

## Problem Statement

The user needs a secure, zero-knowledge unified vault for their postgraduate project in Cybersecurity and Forensic Analysis. The system must ensure that the server infrastructure (OCI) only stores encrypted data and has no capability to read it, keeping data safe even if the server or database is compromised.

## Goals

- [ ] Implement client-side encryption where the master password derives a cryptographic key on the client side, and data is encrypted before network transmission.
- [ ] Isolate the backend API in an OCI VCN behind an Nginx reverse proxy with SSL/TLS termination, exposing only port 443.
- [ ] Implement an immutable audit trail (Trilha Forense) that records every interaction (login failure, file decryption, note change) with Timestamp, IP Address, Action, and Transaction Hash.
- [ ] Develop a modern, responsive frontend with a premium security-focused aesthetic (e.g., dark mode, cyber-security color palette, smooth animations).

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature     | Reason         |
| ----------- | -------------- |
| Plaintext data storage | Violates the Zero-Knowledge principle. |
| Key recovery mechanisms | Compromises the Zero-Knowledge architecture since the server cannot know the key. |
| Direct public access to backend | Violates the OCI isolation requirement. |

---

## Assumptions & Open Questions

Every ambiguity is resolved or recorded here - nothing is left silently unclear.

| Assumption / decision | Chosen default  | Rationale | Confirmed? |
| --------------------- | --------------- | --------- | ---------- |
| Client-Side Framework | A modern web frontend will be built for the UI and client-side encryption. | Provides a premium user experience and executes the Argon2 and AES-256-GCM operations natively in the browser. | y |
| Audit Trail Immutability | Implemented via append-only tables and cryptographic hash chaining (SHA-256). | Prevents tampering with logs, fulfilling the forensic requirement. | y |

**Open questions:** none - all resolved or logged above.

---

## User Stories

### P1: Client-Side Encryption & Storage ⭐ MVP

**User Story**: As a user, I want my data to be encrypted on my device before being sent to the server so that the server never sees my plaintext data.

**Why P1**: Core to the zero-knowledge concept.

**Acceptance Criteria**:

1. The system SHALL accept payloads for files and notes that are already encrypted with AES-256-GCM.
2. The system SHALL NOT store the user's master password in plaintext or in a reversible format.
3. WHEN a user authenticates THEN the system SHALL verify credentials using Argon2 hashing.
4. WHEN storing files THEN the system SHALL save the encrypted blob to OCI Object Storage.
5. WHEN storing notes/metadata THEN the system SHALL save the encrypted text to the OCI Autonomous Database.

**Independent Test**: Can send a dummy encrypted payload via API, verify it's stored exactly as sent in the DB and Object Storage, and cannot be read without the client key.

---

### P2: Forensic Audit Trail

**User Story**: As a forensic analyst, I want an immutable log of all system interactions so that I can audit security events and prove non-repudiation.

**Why P2**: Required for the academic grading (Trilha Forense).

**Acceptance Criteria**:

1. WHEN a significant event occurs (login success/fail, file access/decryption attempt, note update) THEN the system SHALL append an audit record.
2. The system SHALL include Timestamp, IP Address, Action Performed, and Transaction Hash in every audit record.
3. The system SHALL calculate the Transaction Hash by hashing the current record's data combined with the previous record's hash.
4. IF an attempt is made to modify an existing audit log entry THEN the system SHALL reject the operation at the database level.

**Independent Test**: Trigger a series of actions (e.g., failed login), query the audit log to verify the entry contains all required fields, and verify the hash chain is unbroken.

---

### P2: Security-Focused Frontend Aesthetic

**User Story**: As a user, I want a modern, premium, and security-themed interface so that I feel confident and engaged when managing my sensitive data.

**Why P2**: Enhances user trust and engagement, providing a professional and premium feel to the application.

**Acceptance Criteria**:

1. The system SHALL display a dark-mode oriented design with a curated security color palette.
2. WHEN performing cryptographic operations THEN the system SHALL provide visual feedback (micro-animations or indicators).
3. The system SHALL render responsive layouts across desktop and mobile devices.

**Independent Test**: Load the application in a browser and verify the aesthetic design matches modern security tools, and animations trigger during data encryption.

---

### P3: Infrastructure Isolation

**User Story**: As a security administrator, I want the API to be shielded from direct internet access so that the attack surface is minimized.

**Why P3**: Required for the academic grading (Isolamento na OCI).

**Acceptance Criteria**:

1. The system SHALL expose the API only through an Nginx reverse proxy.
2. The system SHALL enforce SSL/TLS termination at the Nginx level.
3. IF traffic arrives on ports other than 443 THEN the system SHALL drop or redirect the connection.
4. WHERE the backend is deployed the system SHALL ensure it only binds to a private VCN IP address.

**Independent Test**: Attempt to curl the FastAPI server directly on its private port from the outside (should fail). Attempt to curl via HTTPS on port 443 (should succeed).

---

## Edge Cases

- IF an audit log entry fails to save THEN the system SHALL reject the triggering transaction to maintain forensic integrity.
- IF an invalid token is provided THEN the system SHALL reject the request and log a failed access attempt.
- WHEN a payload exceeds the maximum allowed file size THEN the system SHALL reject the upload to prevent denial of service.

---

## Requirement Traceability

Each requirement gets a unique ID for tracking across design, tasks, and validation.

| Requirement ID | Story       | Phase  | Status  |
| -------------- | ----------- | ------ | ------- |
| PYV-01      | P1: Client-Side Encryption & Storage | Specify | Pending |
| PYV-02      | P2: Forensic Audit Trail | Specify | Pending |
| PYV-03      | P2: Security-Focused Frontend Aesthetic | Specify | Pending |
| PYV-04      | P3: Infrastructure Isolation | Specify | Pending |

**Coverage:** 4 total, 0 mapped to tasks, 4 unmapped ⚠️

---

## Success Criteria

How we know the feature is successful:

- [ ] Data stored in the OCI Database and Object Storage is indistinguishable from random noise without the client's decryption key.
- [ ] The FastAPI application is only accessible via HTTPS on port 443 through the Nginx proxy.
- [ ] A continuous, unbroken hash chain can be cryptographically verified for all audit logs.
- [ ] A visually striking, premium frontend interface that users associate with high security.
