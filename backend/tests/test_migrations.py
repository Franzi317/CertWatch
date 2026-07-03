import subprocess, sys, os, sqlite3, tempfile, pathlib

BACKEND = pathlib.Path(__file__).resolve().parents[1]

def test_upgrade_head_creates_all_tables(tmp_path):
    db = tmp_path / "m.db"
    env = {**os.environ, "CERTWATCH_DATABASE_URL": f"sqlite:///{db}"}
    r = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"],
                       cwd=BACKEND, env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    con = sqlite3.connect(db)
    names = {row[0] for row in con.execute("select name from sqlite_master where type='table'")}
    assert {"targets", "certificates", "endpoints", "scan_jobs", "alert_events",
            "notification_channels", "system_settings", "audit_logs",
            "certificate_observations"} <= names
    cols = {row[1] for row in con.execute("pragma table_info(targets)")}
    assert {"schedule_type", "schedule_time", "schedule_day"} <= cols
