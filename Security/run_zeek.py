#!/usr/bin/env python3
"""
run_zeek.py - merged_output ki saari pcap par Zeek (docker) chalata hai.

Zaroorat: Python + Docker Desktop (chalta hua) . Pehli baar zeek/zeek:lts image khud download hogi.

Input  : ROOT\\merged_output\\10_cdac_hp_1.pcap  (merge_pcap5.py ka output)
Output : ROOT\\merged_output\\zeek_logs\\10\\cdac_hp_1\\conn.log, dns.log ...
Report : ROOT\\merged_output\\zeek_logs\\zeek_summary.csv

USAGE
  python run_zeek.py "C:\\Users\\P\\Desktop\\pcappapa"                    # saari pcap
  python run_zeek.py "C:\\Users\\P\\Desktop\\pcappapa" --date 10          # sirf date 10
  python run_zeek.py "C:\\Users\\P\\Desktop\\pcappapa" --date 10 --hp 1 3 # date 10, hp 1 aur 3
  python run_zeek.py "C:\\Users\\P\\Desktop\\pcappapa" --force            # pehle ke logs dobara banao
"""
import argparse, csv, datetime, os, re, shutil, subprocess, sys

NAME_RE = re.compile(r"^(\d+)_(cdac_hp_\d+)\.pcap$", re.I)
IMAGE = "zeek/zeek:lts"
HEADER = ["run_time", "date", "honeypot", "pcap_size_MB", "conn_total",
          "tcp", "udp", "icmp", "other", "log_files", "status"]


def count_conn(conn_log):
    """conn.log me total connections aur proto-wise ginti (# wali lines chhod ke)."""
    c = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0}
    if not os.path.isfile(conn_log):
        return c
    idx = None
    with open(conn_log, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#fields"):
                idx = line.rstrip("\n").split("\t").index("proto") - 1
                continue
            if line.startswith("#") or idx is None:
                continue
            p = line.rstrip("\n").split("\t")
            c["total"] += 1
            proto = p[idx] if idx < len(p) else ""
            c[proto if proto in ("tcp", "udp", "icmp") else "other"] += 1
    return c


def upsert_csv(path, header, rows):
    """Key = (date, honeypot). Naya run purani row replace karta hai, baaki rows bachi rehti hain."""
    old = []
    if os.path.isfile(path):
        with open(path, newline="", encoding="utf-8") as f:
            old = list(csv.reader(f))[1:]
    new_keys = {(r[1], r[2]) for r in rows}
    old = [r for r in old if (r[1], r[2]) not in new_keys]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(old + rows)


def docker_ok():
    if not shutil.which("docker"):
        return "docker command nahi mili. Docker Desktop install/start karo."
    r = subprocess.run(["docker", "info"], capture_output=True, text=True)
    if r.returncode != 0:
        return "Docker chal nahi raha. Docker Desktop kholo, 'Engine running' aane do, phir dobara chalao."
    return None


def main():
    ap = argparse.ArgumentParser(description="merged pcap par Zeek chalao")
    ap.add_argument("root", help="main folder (jisme merged_output hai)")
    ap.add_argument("--date", nargs="*", help="sirf ye date(s), e.g. --date 10 18")
    ap.add_argument("--hp", nargs="*", help="sirf ye honeypot number(s), e.g. --hp 1 3")
    ap.add_argument("--merged", help="merged pcap folder (default: ROOT\\merged_output)")
    ap.add_argument("--force", action="store_true", help="logs pehle se hon tab bhi dobara chalao")
    a = ap.parse_args()

    merged = os.path.abspath(a.merged or os.path.join(os.path.abspath(a.root), "merged_output"))
    if not os.path.isdir(merged):
        sys.exit(f"Folder nahi mila: {merged}\nPehle merge_pcap5.py chalao.")

    jobs = []
    for fn in sorted(os.listdir(merged)):
        m = NAME_RE.match(fn)
        if not m:
            continue
        d, hp = m.group(1), m.group(2).lower()
        if a.date and d not in a.date:
            continue
        if a.hp and hp not in [f"cdac_hp_{x}" if x.isdigit() else x.lower() for x in a.hp]:
            continue
        jobs.append((d, hp, os.path.join(merged, fn)))
    if not jobs:
        sys.exit("Koi matching pcap nahi mili (naam aisa hona chahiye: 10_cdac_hp_1.pcap).")

    err = docker_ok()
    if err:
        sys.exit(err)

    logs_root = os.path.join(merged, "zeek_logs")
    os.makedirs(logs_root, exist_ok=True)
    print(f"Merged: {merged}\nJobs  : {len(jobs)}\n")

    rows = []
    for d, hp, pcap in jobs:
        out = os.path.join(logs_root, d, hp)
        size = os.path.getsize(pcap) / 1048576
        print(f"[date {d} | {hp}]  {size:.1f} MB")
        if os.path.isfile(os.path.join(out, "conn.log")) and not a.force:
            print("   logs pehle se hain, skip (dobara karna ho to --force)")
            status = "SKIPPED (already done)"
        else:
            os.makedirs(out, exist_ok=True)
            cmd = ["docker", "run", "--rm",
                   "-v", f"{merged}:/pcap:ro",
                   "-v", f"{out}:/out",
                   "-w", "/out", IMAGE,
                   "zeek", "-C", "-r", f"/pcap/{os.path.basename(pcap)}"]
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0:
                print("   [FAIL] Zeek error:\n   " + (r.stderr.strip() or r.stdout.strip())[-600:].replace("\n", "\n   "))
                status = "FAIL"
            else:
                status = "OK"
                print("   Zeek poora hua")
        c = count_conn(os.path.join(out, "conn.log"))
        logs = sorted(f for f in os.listdir(out) if f.endswith(".log")) if os.path.isdir(out) else []
        print(f"   conn.log: {c['total']} connections (tcp {c['tcp']}, udp {c['udp']}, icmp {c['icmp']}, other {c['other']})")
        print(f"   {len(logs)} log files -> {out}\n")
        rows.append([datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), d, hp, f"{size:.1f}",
                     c["total"], c["tcp"], c["udp"], c["icmp"], c["other"], len(logs), status])

    upsert_csv(os.path.join(logs_root, "zeek_summary.csv"), HEADER, rows)
    print(f"Summary: {os.path.join(logs_root, 'zeek_summary.csv')}\nDone.")


if __name__ == "__main__":
    main()
