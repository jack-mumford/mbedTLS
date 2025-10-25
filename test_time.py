#!/usr/bin/env python3
import subprocess, time, os, signal, sys, re, datetime

ROOT = os.path.dirname(__file__)
SRC = os.path.join(ROOT, "src")
CERTS = os.path.join(ROOT, "certs")

def run(cmd, cwd):
    p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate()
    return p.returncode, out, err

def parse_et_from_output(txt):
    """
    Accept either style:
      1) ET:YYYY-MM-DDThh:mm:ss-04:00
      2) ET time from server: YYYY-MM-DD HH:MM:SS (UTC-4:00)
    Returns: (dt_naive: datetime, offset_str: str like '-04:00')
    """
    m = re.search(r"ET:\s*(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2}):(\d{2})([+-]\d{2}:\d{2})", txt)
    if m:
        y, mo, d = map(int, m.group(1).split("-"))
        H, Mi, S = int(m.group(2)), int(m.group(3)), int(m.group(4))
        off = m.group(5)
        return datetime.datetime(y, mo, d, H, Mi, S), off

    m = re.search(r"ET time from server:\s+(\d{4}-\d{2}-\d{2})\s+(\d{2}):(\d{2}):(\d{2})\s+\(UTC([+-]\d+):(\d{2})\)", txt)
    if m:
        y, mo, d = map(int, m.group(1).split("-"))
        H, Mi, S = int(m.group(2)), int(m.group(3)), int(m.group(4))
        offh, offm = int(m.group(5)), int(m.group(6))
        sign = "+" if offh >= 0 else "-"
        off = f"{sign}{abs(offh):02d}:{offm:02d}"
        return datetime.datetime(y, mo, d, H, Mi, S), off

    return None

def to_epoch_in_tz(dt_naive, tz_name):
    """
    Interpret dt_naive as a local time in tz_name and return the epoch seconds.
    """
    import time as _t, os as _o
    old = _o.environ.get("TZ")
    try:
        _o.environ["TZ"] = tz_name
        _t.tzset()
        return int(time.mktime(dt_naive.timetuple()))
    finally:
        if old is None:
            _o.unsetenv("TZ")
        else:
            _o.environ["TZ"] = old
        _t.tzset()

def main():
    # Build
    rc, out, err = run(["make"], SRC)
    if rc != 0:
        print("Build failed"); print(err); sys.exit(1)

    # Ensure certs
    if not (os.path.exists(os.path.join(CERTS, "server.crt.pem")) and
            os.path.exists(os.path.join(CERTS, "server.key.pem"))):
        rc, out, err = run(["bash", "gen_self_signed.sh"], CERTS)
        if rc != 0:
            print("Cert generation failed:", err); sys.exit(1)

    # Start server
    srv = subprocess.Popen(
        ["./server","127.0.0.1","44330","../certs/server.crt.pem","../certs/server.key.pem"],
        cwd=SRC, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, preexec_fn=os.setsid
    )
    time.sleep(0.8)

    try:
        rc, out, err = run(["./client","127.0.0.1","44330","../certs/server.crt.pem"], SRC)
        print(out.strip())
        if rc != 0:
            print("Client failed:", err); sys.exit(1)

        parsed = parse_et_from_output(out)
        if not parsed:
            print("Could not find ET output. Expected 'ET:...' or 'ET time from server: ...'"); sys.exit(1)

        et_dt, off = parsed

        # Check plausible ET offset
        off_norm = off.replace(" ", "")
        if off_norm not in ("-04:00","-05:00","+04:00","+05:00","+4:00","+5:00","-4:00","-5:00"):
            print("Unexpected ET UTC offset:", off); sys.exit(1)

        # Convert the ET wall-clock to a UTC epoch (same instant), then compare to current UTC time.
        et_epoch_utc = to_epoch_in_tz(et_dt, "America/New_York")
        now_epoch_utc = int(time.time())

        # Tolerance window (seconds) — allow for student/VM slowness and scheduling jitter.
        TOL = 300  # 5 minutes

        # Debug lines for transparency
        print(f"DEBUG: Parsed ET dt: {et_dt}  offset: {off_norm}")
        print(f"DEBUG: ET as UTC epoch: {et_epoch_utc}")
        print(f"DEBUG: Now UTC epoch:   {now_epoch_utc}")
        print(f"DEBUG: |ET - Now|:      {abs(et_epoch_utc - now_epoch_utc)} sec (tol {TOL})")

        if abs(et_epoch_utc - now_epoch_utc) > TOL:
            print("ET time not within expected 'now' window (UTC comparison)."); sys.exit(1)

        print("OK: Time-converter test passed.")
    finally:
        try:
            os.killpg(os.getpgid(srv.pid), signal.SIGTERM)
        except Exception:
            pass

if __name__ == "__main__":
    main()
