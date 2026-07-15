// Thin fetch wrapper. API base is same-origin (/api) in prod, proxied in dev.
const BASE = (import.meta.env.VITE_API_BASE as string) || "/api";
const KEY = (import.meta.env.VITE_API_KEY as string) || "";

// Endpoints that legitimately return 401 as part of the auth flow itself.
// Redirecting to /login on their failure would cause a redirect loop.
const AUTH_CHECK_PATHS = ["/auth/me", "/auth/local"];

async function req<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json", ...(opts.headers as any) };
  if (KEY) headers["Authorization"] = `Bearer ${KEY}`;
  const res = await fetch(`${BASE}${path}`, { ...opts, headers, credentials: "include" });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail || detail;
    } catch {}
    if (res.status === 401 && !AUTH_CHECK_PATHS.some((p) => path.startsWith(p))) {
      window.location.assign("/login");
    }
    throw new Error(detail);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

export const api = {
  get: <T>(p: string) => req<T>(p),
  post: <T>(p: string, body?: any) => req<T>(p, { method: "POST", body: body ? JSON.stringify(body) : undefined }),
  put: <T>(p: string, body: any) => req<T>(p, { method: "PUT", body: JSON.stringify(body) }),
  del: (p: string) => req<void>(p, { method: "DELETE" }),
};

// ---- Auth ----
export interface Me { id: number; email: string; role: string; }

export function getMe(): Promise<Me> {
  return req<Me>("/auth/me");
}

export function loginLocal(email: string, password: string): Promise<Me> {
  return req<Me>("/auth/local", { method: "POST", body: JSON.stringify({ email, password }) });
}

export async function logout(): Promise<void> {
  await req<void>("/auth/logout", { method: "POST" });
}

// ---- Types ----
export interface Target {
  id: number; name: string; description: string; target_type: string; value: string;
  ports: number[]; environment: string; owner: string; tags: string[];
  scan_frequency_minutes: number; schedule_type: string; schedule_time: string; schedule_day: number;
  timeout: number; concurrency: number; enabled: boolean;
  alert_thresholds: number[]; use_sni: boolean; last_scanned_at: string | null; endpoint_count: number;
}
export interface ScanJob {
  id: number; target_id: number | null; target_name: string; status: string; trigger: string;
  total_endpoints: number; scanned_endpoints: number; certs_found: number; errors: number;
  message: string; started_at: string | null; finished_at: string | null; created_at: string;
}
export interface Cert {
  id: number; fingerprint_sha256: string; common_name: string; subject: string; sans: string[];
  issuer: string; issuer_cn: string; serial_number: string; signature_algorithm: string;
  public_key_algorithm: string; public_key_size: number | null; not_before: string | null;
  not_after: string | null; self_signed: boolean; internal_issued: boolean; is_wildcard: boolean; is_ca: boolean;
  chain_length: number; first_seen: string; last_seen: string; days_until_expiry: number | null;
  expired: boolean; severity: string; expiry_phrase: string; endpoint_count: number;
  source: "network" | "ct" | "chain"; pem?: string; endpoints?: Endpoint[]; observations?: Observation[];
}
export interface CaCertificate extends Cert {
  dependent_count: number;
  is_root: boolean;
}
// Other pages call `api.get<T>(path)` inline rather than through named helpers;
// this one is exported as a helper per the CA-hierarchy task spec, but follows
// the same api.get<T> convention (path is relative to the /api BASE).
export const listCaCertificates = () => api.get<{ items: CaCertificate[] }>("/ca-certificates");
export interface WatchedDomain {
  id: number; domain: string; enabled: boolean;
  last_checked_at: string | null; last_crtsh_id: number | null; created_at: string;
}
export interface Endpoint {
  id: number; target_id: number | null; target_name: string; environment: string; owner: string;
  host: string; ip: string; port: number; sni: string; last_status: string; last_status_phrase: string;
  last_error: string; consecutive_failures: number; current_cert_id: number | null;
  common_name: string; issuer_cn: string; not_after: string | null; days_until_expiry: number | null;
  severity: string; expiry_phrase: string; first_seen: string; last_seen: string;
  certificate?: Cert; observations?: Observation[];
}
export interface Observation {
  id: number; scan_job_id: number | null; certificate_id: number | null; status: string;
  status_phrase: string; error: string; sni_used: string; change_status: string; observed_at: string;
}
export interface Alert {
  id: number; rule_type: string; severity: string; threshold_days: number | null; message: string;
  endpoint_id: number | null; endpoint: string; certificate_id: number | null; common_name: string;
  acknowledged: boolean; muted: boolean; muted_until: string | null; resolved: boolean;
  notify_count: number; last_notified_at: string | null; created_at: string;
}
export interface Channel {
  // channel_type is a free string on the backend (no enum/union to widen here);
  // known values: "smtp" | "teams" | "webhook" | "slack" | "pagerduty".
  id: number; name: string; channel_type: string; enabled: boolean; re_alert_hours: number;
  config_summary: Record<string, any>;
}
export interface Issuer {
  id: number; name: string; issuer_type: string; enabled: boolean;
  last_test_at: string | null; last_test_ok: boolean; created_at: string;
  config: Record<string, any>;
}
export interface Dashboard {
  total_certificates: number; total_endpoints: number; expiring_90d: number; ca_expiring_90d: number;
  expiring_30d: number;
  expiring_7d: number; expired: number; failed_scans: number; recently_changed: number;
  open_alerts: number; last_successful_scan: string | null; next_scheduled_scan: string | null;
  managed_certificates: number; unmanaged_certificates: number; orders_in_flight: number;
  orders_pending_approval: number; renewal_success_rate_30d: number | null;
  open_findings: number; findings_by_severity: Record<string, number>;
}
export interface RenewalPolicy {
  id: number; name: string; renew_before_days: number; key_algorithm: string; key_size: number;
  require_approval: boolean; verify_after_deploy: boolean; max_retries: number; created_at: string;
}
export interface ManagedCertificate {
  id: number; common_name: string; sans: string[]; issuer_id: number; renewal_policy_id: number;
  current_certificate_id: number | null; state: string; owner: string; environment: string;
  created_at: string; updated_at: string;
  current_cert_common_name?: string | null; current_cert_not_after?: string | null;
}
export interface DeploymentTargetSummary {
  id: number; name: string; kind: string; enabled: boolean;
  last_deploy_at: string | null; last_deploy_ok: boolean; managed_certificate_id: number;
}
export interface LifecycleTransition { from: string; to: string; at: string; detail: string; }
export interface LifecycleOrder {
  id: number; managed_certificate_id: number; action: string; status: string; attempts: number;
  approved_by: string; approved_at: string | null; error: string; correlation_id: string;
  transitions: LifecycleTransition[]; created_at: string; updated_at: string;
}
export interface Finding {
  id: number; rule_id: string; severity: string; certificate_id: number | null;
  endpoint_id: number | null; title: string; detail: string; dedupe_key: string;
  disposition: string; status: string; first_seen: string; last_seen: string;
  created_at: string; updated_at: string;
}
export interface FindingList { total: number; items: Finding[]; }
export interface ReportSchedule {
  id: number; name: string; report_type: string; filter_params: Record<string, any>;
  format: string; recipients: string[]; channel_id: number; cadence: string;
  schedule_time: string; schedule_day: number; enabled: boolean;
  last_run_at: string | null; created_at: string;
}
