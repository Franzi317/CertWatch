import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { loginLocal } from "../api";

export default function Login() {
  const navigate = useNavigate();
  const [showBreakGlass, setShowBreakGlass] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  function signInWithMicrosoft() {
    window.location.assign("/api/auth/login");
  }

  async function submitBreakGlass(e: FormEvent) {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      await loginLocal(email, password);
      navigate("/", { replace: true });
    } catch (err: any) {
      setError(err.message || "Sign-in failed.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="login-screen">
      <div className="login-card">
        <div className="brand login-brand">Cert<span>Watch</span></div>
        <p className="muted" style={{ marginTop: 0 }}>Sign in to continue.</p>

        <button onClick={signInWithMicrosoft} style={{ width: "100%" }}>
          Sign in with Microsoft
        </button>

        <button
          type="button"
          className="ghost login-breakglass-toggle"
          onClick={() => setShowBreakGlass((v) => !v)}
        >
          {showBreakGlass ? "Hide break-glass admin sign-in" : "Break-glass admin sign-in"}
        </button>

        {showBreakGlass && (
          <form onSubmit={submitBreakGlass} className="login-breakglass-form">
            <div className="field">
              <label htmlFor="login-email">Email</label>
              <input
                id="login-email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="username"
                required
                style={{ width: "100%" }}
              />
            </div>
            <div className="field">
              <label htmlFor="login-password">Password</label>
              <input
                id="login-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
                style={{ width: "100%" }}
              />
            </div>
            <button type="submit" className="secondary" disabled={submitting} style={{ width: "100%" }}>
              {submitting ? "Signing in…" : "Sign in"}
            </button>
          </form>
        )}

        {error && <div className="login-error">{error}</div>}

        <div className="login-notice">
          Authorized internal inventory only. Scan only networks and hosts you are
          authorized to assess.
        </div>
      </div>
    </div>
  );
}
