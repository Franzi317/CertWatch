import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, Endpoint } from "../api";
import { DataTable, SeverityBadge, fmtDate } from "../ui";

export default function Endpoints() {
  const [failedOnly, setFailedOnly] = useState(false);
  const [rows, setRows] = useState<Endpoint[]>([]);
  const [total, setTotal] = useState(0);

  useEffect(() => {
    api.get<{ total: number; items: Endpoint[] }>(`/endpoints?limit=2000${failedOnly ? "&failed=true" : ""}`)
      .then((r) => { setRows(r.items); setTotal(r.total); }).catch(() => {});
  }, [failedOnly]);

  return (
    <>
      <div className="topbar"><h1>Endpoints</h1></div>
      <div className="content">
        <div className="panel">
          <div className="row" style={{ marginBottom: 14 }}>
            <button className={!failedOnly ? "" : "secondary"} onClick={() => setFailedOnly(false)}>All endpoints</button>
            <button className={failedOnly ? "" : "secondary"} onClick={() => setFailedOnly(true)}>Failed scans</button>
            <div className="spacer" />
            <span className="muted">{total} endpoints</span>
          </div>
          <DataTable
            rows={rows}
            searchKeys={["host", "ip", "common_name", "target_name"]}
            columns={[
              { key: "endpoint", header: "Endpoint", render: (e) => <Link to={`/endpoints/${e.id}`}>{e.host || e.ip}:{e.port}</Link>, value: (e) => `${e.host || e.ip}:${e.port}` },
              { key: "ip", header: "IP", render: (e) => <span className="mono">{e.ip || "—"}</span> },
              { key: "common_name", header: "Cert CN", wrap: true, render: (e) => e.current_cert_id ? <Link to={`/certificates/${e.current_cert_id}`}>{e.common_name || "—"}</Link> : "—" },
              { key: "environment", header: "Env" },
              { key: "owner", header: "Owner" },
              { key: "severity", header: "Status", value: (e) => e.days_until_expiry ?? 99999, render: (e) => <SeverityBadge severity={e.severity} label={e.expiry_phrase} /> },
              { key: "not_after", header: "Expires", value: (e) => e.not_after || "", render: (e) => fmtDate(e.not_after) },
            ]}
            empty="No endpoints. Run a scan from the Targets page."
          />
        </div>
      </div>
    </>
  );
}
