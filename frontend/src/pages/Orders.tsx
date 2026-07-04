import { Fragment, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, LifecycleOrder, ManagedCertificate } from "../api";
import { useAuth } from "../auth";
import { fmtDate, SeverityBadge, useToast } from "../ui";

const STATUS_SEVERITY: Record<string, string> = {
  pending_approval: "warning", approved: "info", queued: "info", issuing: "info",
  deploying: "info", verifying: "info", complete: "healthy", failed: "critical",
  rolled_back: "critical",
};

export default function Orders() {
  const [orders, setOrders] = useState<LifecycleOrder[]>([]);
  const [managed, setManaged] = useState<Record<number, ManagedCertificate>>({});
  const [expanded, setExpanded] = useState<number | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const { user } = useAuth();
  const { show, node } = useToast();
  const canApprove = user && (user.role === "operator" || user.role === "admin");

  const load = () => api.get<LifecycleOrder[]>("/lifecycle/orders").then(setOrders).catch((e) => show(e.message, true));
  useEffect(() => {
    load();
    api.get<ManagedCertificate[]>("/managed-certificates")
      .then((rows) => setManaged(Object.fromEntries(rows.map((m) => [m.id, m]))))
      .catch(() => {});
  }, []);

  function certLabel(id: number): string {
    const m = managed[id];
    return m ? (m.common_name || `#${id}`) : `#${id}`;
  }

  async function approve(o: LifecycleOrder) {
    setBusy(o.id);
    try {
      await api.post(`/lifecycle/orders/${o.id}/approve`);
      show(`Order ${o.id} approved.`);
      load();
    } catch (e: any) {
      // The API returns 403 with detail "revoke approval requires admin" for the
      // two-person rule on revoke orders — surface that message as-is.
      show(`Approve failed: ${e.message}`, true);
    } finally { setBusy(null); }
  }

  async function reject(o: LifecycleOrder) {
    if (!confirm(`Reject order ${o.id} (${o.action} for ${certLabel(o.managed_certificate_id)})?`)) return;
    setBusy(o.id);
    try {
      await api.post(`/lifecycle/orders/${o.id}/reject`);
      show(`Order ${o.id} rejected.`);
      load();
    } catch (e: any) {
      show(`Reject failed: ${e.message}`, true);
    } finally { setBusy(null); }
  }

  return (
    <>
      <div className="topbar"><h1>Lifecycle Orders</h1></div>
      <div className="content">
        <div className="panel">
          <table>
            <thead>
              <tr>
                <th>Managed Certificate</th><th>Action</th><th>Status</th>
                <th>Created</th><th>Updated</th><th></th>
              </tr>
            </thead>
            <tbody>
              {orders.map((o) => (
                <Fragment key={o.id}>
                  <tr>
                    <td><Link to={`/managed-certificates`}>{certLabel(o.managed_certificate_id)}</Link></td>
                    <td>{o.action}</td>
                    <td><SeverityBadge severity={STATUS_SEVERITY[o.status] || "info"} label={o.status} /></td>
                    <td>{fmtDate(o.created_at)}</td>
                    <td>{fmtDate(o.updated_at)}</td>
                    <td>
                      <div className="row" style={{ gap: 4 }}>
                        <button className="ghost" onClick={() => setExpanded(expanded === o.id ? null : o.id)}>
                          {expanded === o.id ? "Hide" : "Timeline"}
                        </button>
                        {o.status === "pending_approval" && canApprove && (
                          <>
                            <button disabled={busy === o.id} onClick={() => approve(o)}>Approve</button>
                            <button className="ghost" style={{ color: "var(--critical)" }}
                              disabled={busy === o.id} onClick={() => reject(o)}>Reject</button>
                          </>
                        )}
                        {o.status === "pending_approval" && !canApprove && (
                          <span className="muted">viewer — no approval rights</span>
                        )}
                      </div>
                    </td>
                  </tr>
                  {expanded === o.id && (
                    <tr>
                      <td colSpan={6}>
                        <div className="panel" style={{ margin: "8px 0" }}>
                          <h2>State timeline</h2>
                          {o.transitions.length === 0 ? (
                            <div className="empty">No transitions recorded.</div>
                          ) : (
                            <table>
                              <thead><tr><th>From</th><th>To</th><th>At</th><th>Detail</th></tr></thead>
                              <tbody>
                                {o.transitions.map((t, i) => (
                                  <tr key={i}>
                                    <td>{t.from || "—"}</td>
                                    <td>{t.to}</td>
                                    <td>{fmtDate(t.at)}</td>
                                    <td className="wrap">{t.detail || "—"}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          )}
                          {o.error && <div className="muted" style={{ marginTop: 8 }}>Error: {o.error}</div>}
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
          {orders.length === 0 && <div className="empty">No lifecycle orders yet.</div>}
        </div>
      </div>
      {node}
    </>
  );
}
