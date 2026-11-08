# CCS Verifier

**Runtime Behavior Evidence verification for MCP servers.**

Implements RFC 9334 Remote Attestation concepts for AI Agent security.

## Overview

CCS Verifier (Correctover Certification Standard Verifier) is the core product for Correctover's "Runtime Behavior Notary" strategy. It collects, hashes, evaluates, and cryptographically attests to the actual runtime behavior of MCP servers.

### Key Design Principles

- **Fail-closed**: If evidence is incomplete or tampered, the verdict is FAIL
- **Cryptographically verifiable**: Every attestation can be independently verified using Ed25519 signatures
- **MCP-native**: Designed specifically for MCP server behavior monitoring
- **Evidence-based**: Decisions are based on observed runtime behavior, not static analysis

## Installation

```bash
npm install
```

## Build

```bash
npx tsc
```

## Test

```bash
npm test
```

## Usage

```typescript
import { Verifier, EvidenceCollector } from "ccs-verifier";

// Define what the MCP server declares about itself
const declaredIdentity = {
  name: "my-mcp-server",
  version: "1.0.0",
  allowedTools: ["read_file", "search"],
  allowedEndpoints: ["https://api.example.com"],
  allowedFilePatterns: ["/workspace/**"],
  declaredPermissionScope: "read_write",
};

// Collect runtime behavior evidence
const collector = new EvidenceCollector("server-001", declaredIdentity);
collector
  .recordToolCall("read_file", { path: "/workspace/config.json" })
  .recordNetworkRequest("https://api.example.com/v1/data", "GET", 200);

const evidence = collector.build();

// Verify and get a signed attestation
const verifier = new Verifier();
const { verdict, attestation } = verifier.verifyAndAttest(evidence);

console.log(verdict.status); // "PASS"
```

## Security Policy Rules

| Rule ID | Name | Severity |
|---------|------|----------|
| CCS-001 | No unauthorized data exfiltration | Critical |
| CCS-002 | No permission escalation beyond declared scope | Critical |
| CCS-003 | All tool calls within allowed set | Major |
| CCS-004 | Network requests only to declared endpoints | Major |
| CCS-005 | Behavior matches declared identity/capabilities | Minor |

## License

MIT
