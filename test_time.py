
import subprocess, time, os, signal, sys, re, datetime

ROOT = os.path.dirname(__file__)
SRC = os.path.join(ROOT, "src")
CERTS = os.path.join(ROOT, "certs")

def run(cmd, cwd):
    p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate()
    return p.returncode, out, err

def parse_et_from_output(txt):
    m = re.search(r"(ET:\s*\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})([+-]\d{2}:\d{2})", txt)
    if m:
        iso = m.group(1).split("ET:")[-1].strip()
        off = m.group(2)
        return ("iso1", iso, off)
    m = re.search(r"ET time from server:\s+(\d{4}-\d{2}-\d{2})\s+(\d{2}):(\d{2}):(\d{2})\s+\(UTC([+-]\d+):(\d{2})\)", txt)
    if m:
        date = m.group(1)
        h,mi,s = int(m.group(2)), int(m.group(3)), int(m.group(4))
        offh, offm = int(m.group(5)), int(m.group(6))
        return ("iso2", f"{date} {h:02d}:{mi:02d}:{s:02d}", f"{offh:+d}:{offm:02d}")
    return None

def to_epoch_in_tz(dt_naive, tz_name):
    import time as _t, os as _o
    old = _o.environ.get("TZ")
    try:
        _o.environ["TZ"] = tz_name
        _t.tzset()
        import time
        return int(time.mktime(dt_naive.timetuple()))
    finally:
        if old is None:
            _o.unsetenv("TZ")
        else:
            _o.environ["TZ"] = old
        _t.tzset()

def now_epoch_in_pt():
    import time as _t, os as _o, time
    old = _o.environ.get("TZ")
    try:
        _o.environ["TZ"] = "America/Los_Angeles"
        _t.tzset()
        return int(time.time())
    finally:
        if old is None:
            _o.unsetenv("TZ")
        else:
            _o.environ["TZ"] = old
        _t.tzset()

def main():
    rc, out, err = run(["make"], SRC)
    if rc != 0:
        print("Build failed"); print(err); sys.exit(1)

    if not (os.path.exists(os.path.join(CERTS,"server.crt.pem")) and os.path.exists(os.path.join(CERTS,"server.key.pem"))):
        rc, out, err = run(["bash","gen_self_signed.sh"], CERTS)
        if rc != 0:
            print("Cert generation failed:", err); sys.exit(1)

    srv = subprocess.Popen(["./server","127.0.0.1","44330","../certs/server.crt.pem","../certs/server.key.pem"],
                           cwd=SRC, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, preexec_fn=os.setsid)
    time.sleep(0.8)
    try:
        rc, out, err = run(["./client","127.0.0.1","44330","../certs/server.crt.pem"], SRC)
        print(out.strip())
        if rc != 0:
            print("Client failed:", err); sys.exit(1)

        parsed = parse_et_from_output(out)
        if not parsed:
            print("Could not find ET output. Complete the TODOs and try again."); sys.exit(1)

        fmt, value, off = parsed
        off_norm = off.replace(" ", "")
        if off_norm not in ("-04:00","-05:00","+04:00","+05:00","+4:00","+5:00","-4:00","-5:00"):
            print("Unexpected ET UTC offset:", off); sys.exit(1)

        import datetime
        if fmt == "iso1":
            dt = datetime.datetime.strptime(value.replace("T"," "), "%Y-%m-%d %H:%M:%S")
        else:
            dt = datetime.datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        et_epoch = to_epoch_in_tz(dt, "America/New_York")
        now_pt_epoch = now_epoch_in_pt()
        ok = False
        for hrs in (2,3):
            if abs(et_epoch - (now_pt_epoch + hrs*3600)) <= 300:
                ok = True
                break
        if not ok:
            print("ET time not within expected PT+2h/3h window."); sys.exit(1)

        print("OK: Time-converter test passed.")
    finally:
        try:
            os.killpg(os.getpgid(srv.pid), signal.SIGTERM)
        except Exception:
            pass

if __name__ == "__main__":
    main()
