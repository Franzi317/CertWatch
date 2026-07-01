// Thin fetch wrapper. API base is same-origin (/api) in prod, proxied in dev.
const BASE = (import.meta.env.VITE_API_BASE as string) || "/api";
const KEY = (import.meta.env.VITE_API_KEY as string) || "";

async function req<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json", ...(opts.headers as any) };
  if (KEY) headers["Authorization"] = `Bearer ${KEY}`;
  const res = await fetch(`${BASE}${path}`, { ...opts, headers });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail || detail;
    } catch {}
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
  pem?: string; endpoints?: Endpoint[]; observations?: Observation[];
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
  id: number; name: string; channel_type: string; enabled: boolean; re_alert_hours: number;
  config_summary: Record<string, any>;
}
export interface Dashboard {
  total_certificates: number; total_endpoints: number; expiring_90d: number; expiring_30d: number;
  expiring_7d: number; expired: number; failed_scans: number; recently_changed: number;
  open_alerts: number; last_successful_scan: string | null; next_scheduled_scan: string | null;
}
