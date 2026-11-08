/**
 * CCS Verifier - Default Security Policies
 *
 * Built-in policy rules implementing core security invariants for MCP servers:
 * 1. No unauthorized data exfiltration
 * 2. No permission escalation beyond declared scope
 * 3. All tool calls within allowed set
 * 4. Network requests only to declared endpoints
 * 5. Behavior matches declared identity/capabilities
 */

import type {
  SecurityPolicy,
  PolicyRule,
  PolicyCheckResult,
  RuntimeBehaviorEvidence,
  RuntimeBehaviorEvent,
  DeclaredIdentity,
  PermissionScope,
} from "./types";

// ─── Helper ──────────────────────────────────────────────────────────────────

function getEventsByCategory(
  evidence: RuntimeBehaviorEvidence,
  category: string,
): RuntimeBehaviorEvent[] {
  return evidence.events.filter((e) => e.category === category);
}

function pass(ruleId: string, ruleName: string): PolicyCheckResult {
  return { ruleId, ruleName, passed: true };
}

function fail(
  ruleId: string,
  ruleName: string,
  reason: string,
  violatingEvents?: RuntimeBehaviorEvent[],
): PolicyCheckResult {
  return { ruleId, ruleName, passed: false, reason, violatingEvents };
}

// ─── Permission Scope Ordering ───────────────────────────────────────────────

const SCOPE_LEVELS: Record<PermissionScope, number> = {
  read_only: 0,
  read_write: 1,
  admin: 2,
  unrestricted: 3,
};

function scopeLevel(scope: PermissionScope): number {
  return SCOPE_LEVELS[scope] ?? -1;
}

// ─── Rule 1: No Unauthorized Data Exfiltration ───────────────────────────────

const noDataExfiltration: PolicyRule = {
  ruleId: "CCS-001",
  ruleName: "No unauthorized data exfiltration",
  category: "data_access",
  evaluate(evidence: RuntimeBehaviorEvidence, declared: DeclaredIdentity): PolicyCheckResult {
    const dataEvents = getEventsByCategory(evidence, "data_access");
    const networkEvents = getEventsByCategory(evidence, "network_requests");

    // Check for data_access events that reference external transfers
    const exfilEvents = dataEvents.filter((e) => {
      const action = String(e.payload.action ?? "").toLowerCase();
      return action === "export" || action === "transfer" || action === "exfiltrate";
    });

    // Check for network requests to undeclared endpoints sending data
    const undeclaredNetworkEvents = networkEvents.filter((e) => {
      const url = String(e.payload.url ?? "");
      const method = String(e.payload.method ?? "GET").toUpperCase();
      const hasBody = method !== "GET" && method !== "HEAD";
      const isDeclaredEndpoint = declared.allowedEndpoints.some((endpoint) =>
        url.startsWith(endpoint),
      );
      return hasBody && !isDeclaredEndpoint;
    });

    const violators = [...exfilEvents, ...undeclaredNetworkEvents];

    if (violators.length > 0) {
      return fail(
        "CCS-001",
        "No unauthorized data exfiltration",
        `Found ${violators.length} potential data exfiltration event(s)`,
        violators,
      );
    }

    return pass("CCS-001", "No unauthorized data exfiltration");
  },
};

// ─── Rule 2: No Permission Escalation ────────────────────────────────────────

const noPermissionEscalation: PolicyRule = {
  ruleId: "CCS-002",
  ruleName: "No permission escalation beyond declared scope",
  category: "permission_escalation",
  evaluate(evidence: RuntimeBehaviorEvidence, declared: DeclaredIdentity): PolicyCheckResult {
    const escalationEvents = getEventsByCategory(evidence, "permission_escalation");

    if (escalationEvents.length === 0) {
      return pass("CCS-002", "No permission escalation beyond declared scope");
    }

    const declaredLevel = scopeLevel(declared.declaredPermissionScope);

    const violators = escalationEvents.filter((e) => {
      const requestedScope = String(e.payload.requestedScope ?? "read_only");
      return scopeLevel(requestedScope as PermissionScope) > declaredLevel;
    });

    if (violators.length > 0) {
      return fail(
        "CCS-002",
        "No permission escalation beyond declared scope",
        `Found ${violators.length} permission escalation(s) beyond declared scope "${declared.declaredPermissionScope}"`,
        violators,
      );
    }

    return pass("CCS-002", "No permission escalation beyond declared scope");
  },
};

// ─── Rule 3: Tool Calls Within Allowed Set ───────────────────────────────────

const toolCallsWithinAllowedSet: PolicyRule = {
  ruleId: "CCS-003",
  ruleName: "All tool calls within allowed set",
  category: "tool_calls",
  evaluate(evidence: RuntimeBehaviorEvidence, declared: DeclaredIdentity): PolicyCheckResult {
    const toolEvents = getEventsByCategory(evidence, "tool_calls");
    const allowedSet = new Set(declared.allowedTools);

    const violators = toolEvents.filter((e) => {
      const toolName = String(e.payload.toolName ?? "");
      return !allowedSet.has(toolName);
    });

    if (violators.length > 0) {
      const toolNames = violators.map((e) => String(e.payload.toolName ?? "unknown"));
      return fail(
        "CCS-003",
        "All tool calls within allowed set",
        `Unauthorized tool call(s): ${[...new Set(toolNames)].join(", ")}`,
        violators,
      );
    }

    return pass("CCS-003", "All tool calls within allowed set");
  },
};

// ─── Rule 4: Network Requests to Declared Endpoints Only ─────────────────────

const networkRequestsToDeclaredEndpoints: PolicyRule = {
  ruleId: "CCS-004",
  ruleName: "Network requests only to declared endpoints",
  category: "network_requests",
  evaluate(evidence: RuntimeBehaviorEvidence, declared: DeclaredIdentity): PolicyCheckResult {
    const networkEvents = getEventsByCategory(evidence, "network_requests");

    const violators = networkEvents.filter((e) => {
      const url = String(e.payload.url ?? "");
      return !declared.allowedEndpoints.some((endpoint) => url.startsWith(endpoint));
    });

    if (violators.length > 0) {
      const urls = violators.map((e) => String(e.payload.url ?? "unknown"));
      return fail(
        "CCS-004",
        "Network requests only to declared endpoints",
        `Request(s) to undeclared endpoint(s): ${[...new Set(urls)].join(", ")}`,
        violators,
      );
    }

    return pass("CCS-004", "Network requests only to declared endpoints");
  },
};

// ─── Rule 5: Behavior Matches Declared Identity ──────────────────────────────

const behaviorMatchesIdentity: PolicyRule = {
  ruleId: "CCS-005",
  ruleName: "Behavior matches declared identity/capabilities",
  category: "all",
  evaluate(evidence: RuntimeBehaviorEvidence, declared: DeclaredIdentity): PolicyCheckResult {
    // Check file operations against declared file patterns
    const fileEvents = getEventsByCategory(evidence, "file_operations");
    const violators = fileEvents.filter((e) => {
      const filePath = String(e.payload.path ?? "");
      return !declared.allowedFilePatterns.some((pattern) => {
        // Simple glob matching: support * and ** patterns
        const regexStr = pattern
          .replace(/\*\*/g, "{{GLOBSTAR}}")
          .replace(/\*/g, "[^/]*")
          .replace(/\{\{GLOBSTAR\}\}/g, ".*");
        return new RegExp(`^${regexStr}$`).test(filePath);
      });
    });

    if (violators.length > 0) {
      const paths = violators.map((e) => String(e.payload.path ?? "unknown"));
      return fail(
        "CCS-005",
        "Behavior matches declared identity/capabilities",
        `File operation(s) outside declared patterns: ${[...new Set(paths)].join(", ")}`,
        violators,
      );
    }

    return pass("CCS-005", "Behavior matches declared identity/capabilities");
  },
};

// ─── Default Policy ──────────────────────────────────────────────────────────

/** The default CCS security policy with all standard rules. */
export const DEFAULT_POLICY: SecurityPolicy = {
  policyId: "CCS-DEFAULT-2026-01",
  name: "CCS Default Security Policy",
  version: "1.0.0",
  rules: [
    noDataExfiltration,
    noPermissionEscalation,
    toolCallsWithinAllowedSet,
    networkRequestsToDeclaredEndpoints,
    behaviorMatchesIdentity,
  ],
};
