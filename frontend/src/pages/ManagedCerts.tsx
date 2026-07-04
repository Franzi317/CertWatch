import { Fragment, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, DeploymentTargetSummary, Issuer, ManagedCertificate } from "../api";
import { fmtDate, SeverityBadge, useToast } from "../ui";

const STATE_SEVERITY: Record<string, string> = {
  active: "healthy", renewing: "info", error: "critical", retired: "",
};

export default function ManagedCerts() {
  const [rows, setRows] = useState<ManagedCertificate[]>([]);
  const [issuers, setIssuers] = useState<Issuer[]>([]);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [targets, setTargets] = useState<Record<number, DeploymentTargetSummary[]>>({});
  const { show, node } = useToast();

  const load = () => api.get<ManagedCertificate[]>("/managed-certificates").then(setRows).catch((e) => show(e.message, true));
  useEffect(() => {
    load();
    api.get<Issuer[]>("/issuers").then(setIssuers).catch(() => {});
  }, []);

  function issuerName(id: number): string {
    return issuers.find((i) => i.id === id)?.name || `#${id}`;
  }

  async function toggle(m: ManagedCertificate) {
    if (expanded === m.id) { setExpanded(null); return; }
    setExpanded(m.id);
    if (!targets[m.id]) {
      try {
        const t = await api.get<DeploymentTargetSummary[]>(`/managed-certificates/${m.id}/deployment-targets`);
        setTargets((prev) => ({ ...prev, [m.id]: t }));
      } catch (e: any) { show(e.message, true); }
    }
  }

  return (
    <>
      <div className="topbar"><h1>Managed Certificates</h1></div>
      <div className="content">
        <div className="panel">
          <table>
            <thead>
              <tr>
                <th>Common Name</th><th>State</th><th>Issuer</th><th>Expires</th>
                <th>Owner</th><th>Environment</th><th></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((m) => (
                <Fragment key={m.id}>
                  <tr>
                    <td>{m.common_name || "—"}</td>
                    <td><SeverityBadge severity={STATE_SEVERITY[m.state] || "info"} label={m.state} /></td>
                    <td>{issuerName(m.issuer_id)}</td>
                    <td>{fmtDate(m.current_cert_not_after)}</td>
                    <td>{m.owner || "—"}</td>
                    <td>{m.environment}</td>
                    <td><button className="ghost" onClick={() => toggle(m)}>{expanded === m.id ? "Hide" : "Details"}</button></td>
                  </tr>
                  {expanded === m.id && (
                    <tr>
                      <td colSpan={7}>
                        <div className="panel" style={{ margin: "8px 0" }}>
                          <dl className="kv">
                            <dt>Lifecycle state</dt><dd>{m.state}</dd>
                            <dt>Current certificate</dt>
                            <dd>
                              {m.current_certificate_id ? (
                                <Link to={`/certificates/${m.current_certificate_id}`}>
                                  {m.current_cert_common_name || `#${m.current_certificate_id}`}
                                </Link>
                              ) : "—"}
                            </dd>
                            <dt>Current cert expiry</dt><dd>{fmtDate(m.current_cert_not_after)}</dd>
                            <dt>Subject Alt Names</dt><dd>{m.sans.length ? m.sans.join(", ") : "—"}</dd>
                            <dt>Last updated</dt><dd>{fmtDate(m.updated_at)}</dd>
                          </dl>
                          <h2 style={{ marginTop: 12 }}>Deployment targets</h2>
                          {(targets[m.id] || []).length === 0 ? (
                            <div className="empty">No deployment targets linked to this certificate.</div>
                          ) : (
                            <table>
                              <thead><tr><th>Name</th><th>Kind</th><th>Enabled</th><th>Last deploy</th></tr></thead>
                              <tbody>
                                {(targets[m.id] || []).map((t) => (
                                  <tr key={t.id}>
                                    <td>{t.name}</td>
                                    <td>{t.kind.toUpperCase()}</td>
                                    <td>{t.enabled ? "yes" : "no"}</td>
                                    <td>
                                      {t.last_deploy_at ? (
                                        <SeverityBadge severity={t.last_deploy_ok ? "healthy" : "critical"}
                                          label={`${t.last_deploy_ok ? "ok" : "failed"} — ${fmtDate(t.last_deploy_at)}`} />
                                      ) : <span className="muted">never deployed</span>}
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
          {rows.length === 0 && (
            <div className="empty">
              No managed certificates yet. Promote one from a certificate's detail page ("Manage this certificate").
            </div>
          )}
        </div>
      </div>
      {node}
    </>
  );
}
