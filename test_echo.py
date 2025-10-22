
import subprocess, time, os, signal, sys, re

ROOT = os.path.dirname(__file__)
SRC = os.path.join(ROOT, "src")
CERTS = os.path.join(ROOT, "certs")

def run(cmd, cwd):
    p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate()
    return p.returncode, out, err

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
        if "Server replied:" not in out or "HELLO FROM CLIENT" not in out:
            print("Echo output mismatch"); sys.exit(1)
        print("OK: Echo test passed.")
    finally:
        try:
            os.killpg(os.getpgid(srv.pid), signal.SIGTERM)
        except Exception:
            pass

if __name__ == "__main__":
    main()
