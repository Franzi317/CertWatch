import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, Endpoint } from "../api";
import { SeverityBadge, fmtDate } from "../ui";

export default function EndpointDetail() {
  const { id } = useParams();
  const [e, setE] = useState<Endpoint | null>(null);

  useEffect(() => { api.get<Endpoint>(`/endpoints/${id}`).then(setE).catch(() => {}); }, [id]);
  if (!e) return <div className="content">Loading…</div>;

  return (
    <>
      <div className="topbar">
        <h1>{e.host || e.ip}:{e.port}</h1>
        <SeverityBadge severity={e.severity} label={e.expiry_phrase} />
      </div>
      <div className="content">
        <div className="panel">
          <h2>Endpoint</h2>
          <dl className="kv">
            <dt>Host</dt><dd>{e.host || "—"}</dd>
            <dt>IP</dt><dd className="mono">{e.ip || "—"}</dd>
            <dt>Port</dt><dd>{e.port}</dd>
            <dt>SNI used</dt><dd className="mono">{e.sni || "—"}</dd>
            <dt>Target</dt><dd>{e.target_name} ({e.environment})</dd>
            <dt>Owner</dt><dd>{e.owner || "—"}</dd>
            <dt>Last scan status</dt><dd>{e.last_status_phrase}</dd>
            {e.last_error && <><dt>Last error</dt><dd>{e.last_error}</dd></>}
            <dt>Consecutive failures</dt><dd>{e.consecutive_failures}</dd>
            <dt>First seen</dt><dd>{fmtDate(e.first_seen)}</dd>
            <dt>Last seen</dt><dd>{fmtDate(e.last_seen)}</dd>
          </dl>
        </div>

        {e.certificate && (
          <div className="panel">
            <h2>Current certificate</h2>
            <dl className="kv">
              <dt>Common Name</dt><dd><Link to={`/certificates/${e.certificate.id}`}>{e.certificate.common_name}</Link></dd>
              <dt>Issuer</dt><dd>{e.certificate.issuer_cn}</dd>
              <dt>SANs</dt><dd>{e.certificate.sans.join(", ") || "—"}</dd>
              <dt>Expires</dt><dd>{fmtDate(e.certificate.not_after)} ({e.certificate.expiry_phrase})</dd>
              <dt>Fingerprint</dt><dd className="mono">{e.certificate.fingerprint_sha256}</dd>
            </dl>
          </div>
        )}

        <div className="panel">
          <h2>Scan history</h2>
          <table>
            <thead><tr><th>When</th><th>Status</th><th>Change</th><th>Error</th></tr></thead>
            <tbody>
              {(e.observations || []).map((o) => (
                <tr key={o.id}>
                  <td>{fmtDate(o.observed_at)}</td>
                  <td>{o.status_phrase}</td>
                  <td>{o.change_status || "—"}</td>
                  <td className="wrap muted">{o.error || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
