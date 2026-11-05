export type Severity = "critical" | "high" | "medium" | "low";
export type FindingStatus = "new" | "triaged" | "false_positive" | "disclosed" | "remediated";
export type SafeFinding = {
  fingerprint: string; repository_full_name: string; ecosystem: string; severity: Severity;
  rule_id: string; description?: string; file_path: string; line_number?: number|null;
  commit_sha?: string; date?: string;
};
