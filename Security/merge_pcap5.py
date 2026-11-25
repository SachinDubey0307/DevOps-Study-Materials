#!/usr/bin/env python3
"""
merge_pcap5.py - Date + Honeypot wise PCAP consolidator + DATA-LOSS VERIFICATION

Folder structure:
    ROOT\\ (e.g. C:\\Users\\P\\Desktop\\pcappapa)
      10\\ -> 00.34\\ -> cdac_hp_1\\log ... (date -> time slot -> honeypot -> pcap)

USAGE
  python merge_pcap5.py "C:\\Users\\P\\Desktop\\pcappapa" --date 10 --hp all
  python merge_pcap5.py "C:\\Users\\P\\Desktop\\pcappapa" --date 18 25 26 27 --hp all
  python merge_pcap5.py "C:\\Users\\P\\Desktop\\pcappapa" --date 10 --hp 1 3
  python merge_pcap5.py "C:\\Users\\P\\Desktop\\pcappapa" --date 10          (sab honeypots ek file)
  Extra: --out "D:\\merged"

VERIFICATION (har output ke liye automatic):
  1. Har input file ke packets, bytes, time range ki detail print hoti hai
  2. Merge ke baad OUTPUT file ko dobara padhkar packets/bytes gine jate hain
  3. Content fingerprint (har packet ka time+data) input vs output match kiya jata hai
  4. Result: PASS (koi loss nahi) ya FAIL (mismatch)
  5. CSV reports: merged_output\\verification_summary.csv aur verification_details.csv
     (alag-alag date chalane par rows jud jati hain, overwrite nahi hoti)
"""
import argparse, csv, datetime, hashlib, heapq, os, re, struct, sys, zlib

MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\x4d\x3c\xb2\xa1": ("<", True),
    b"\xa1\xb2\x3c\x4d": (">", True),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
HP_RE = re.compile(r"^cdac_hp_\d+$", re.I)
M64 = (1 << 64) - 1


def probe(path):
    try:
        with open(path, "rb") as f:
            h = f.read(24)
    except OSError:
        return None, None
    if h[:4] in MAGICS and len(h) == 24:
        end, nano = MAGICS[h[:4]]
        snaplen, link = struct.unpack(end + "II", h[16:24])
        return "pcap", (end, nano, snaplen, link)
    if h[:4] == PCAPNG_MAGIC:
        return "pcapng", None
    return None, None


def file_hash(path):
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fp_add(fp, ts, orig, data):
    """Order-independent fingerprint: har packet (time+orig_len+data) ka crc, 64-bit sum."""
    return (fp + zlib.crc32(struct.pack("<QI", ts, orig) + data)) & M64


def fmt(ts_ns):
    return datetime.datetime.fromtimestamp(ts_ns / 1e9).strftime("%Y-%m-%d %H:%M:%S") if ts_ns else "-"


def find_pcaps(folder, hp=None):
    """(found, dup_skipped, pcapng_skipped)"""
    found, seen, dups, ng = [], {}, [], []
    for dp, dirs, files in os.walk(folder):
        dirs.sort()
        rel = os.path.relpath(dp, folder).split(os.sep)
        if hp and hp.lower() not in (x.lower() for x in rel):
            continue
        for fn in sorted(files):
            p = os.path.join(dp, fn)
            kind, info = probe(p)
            if kind == "pcapng":
                ng.append(p)
            elif kind == "pcap":
                hsh = file_hash(p)
                if hsh in seen:
                    dups.append((p, seen[hsh]))
                    continue
                seen[hsh] = p
                found.append((p, info))
    return found, dups, ng


def read_packets(path, end, nano):
    """Returns (sorted_items, stats)."""
    hdr = struct.Struct(end + "IIII")
    items = []
    st = dict(records=0, zero=0, trunc_bytes=0, bytes=0, fp=0, first=0, last=0,
              size=os.path.getsize(path), reordered=False)
    with open(path, "rb") as f:
        f.seek(24)
        while True:
            b = f.read(16)
            if len(b) < 16:
                st["trunc_bytes"] += len(b)  # file ke end me adhoora header
                break
            sec, frac, incl, orig = hdr.unpack(b)
            if sec == 0 and frac == 0 and incl == 0 and orig == 0:
                st["zero"] += 1
                continue
            data = f.read(incl)
            if len(data) < incl:  # adhoora packet
                st["trunc_bytes"] += 16 + len(data)
                break
            ts = sec * 10**9 + (frac if nano else frac * 1000)
            items.append((ts, orig, data))
            st["records"] += 1
            st["bytes"] += len(data)
            st["fp"] = fp_add(st["fp"], ts, orig, data)
    if items:
        if any(items[i][0] > items[i + 1][0] for i in range(len(items) - 1)):
            items.sort(key=lambda x: x[0])
            st["reordered"] = True
        st["first"], st["last"] = items[0][0], items[-1][0]
    return items, st


def verify_output(out_path):
    """Nayi file ko dobara padhkar (packets, bytes, fingerprint, first, last)."""
    n = tot = fp = 0
    first = last = 0
    with open(out_path, "rb") as f:
        g = f.read(24)
        end, nano = MAGICS[g[:4]]
        hdr = struct.Struct(end + "IIII")
        while True:
            b = f.read(16)
            if len(b) < 16:
                break
            sec, frac, incl, orig = hdr.unpack(b)
            data = f.read(incl)
            ts = sec * 10**9 + (frac if nano else frac * 1000)
            n += 1
            tot += len(data)
            fp = fp_add(fp, ts, orig, data)
            first = first or ts
            last = ts
    return n, tot, fp, first, last


def merge(date, hp, folder, out_path, hp_filter, summary, details):
    files, dups, ng = find_pcaps(folder, hp_filter)
    warns = []
    for p in ng:
        warns.append(f"pcapng skip: {p}")
    if not files:
        print("   [!] koi pcap file nahi mili")
        summary.append([date, hp, 0, 0, 0, 0, 0, 0, "-", "NO FILES", "; ".join(warns)])
        return

    links = [i[3] for _, i in files]
    link = max(set(links), key=links.count)
    if len(set(links)) > 1:
        warns.append(f"alag link-types {set(links)}; sirf {link} li gayi")
        files = [(p, i) for p, i in files if i[3] == link]
    snaplen = max(i[2] for _, i in files)

    # ---- 1) INPUT detail ----
    print(f"   INPUT FILES ({len(files)}):")
    print(f"   {'#':>3}  {'packets':>8}  {'bytes':>11}  {'first':19}  {'last':19}  file")
    streams, in_pk, in_by, in_fp, in_first, in_last = [], 0, 0, 0, 0, 0
    zero_total = trunc_total = 0
    for k, (p, i) in enumerate(files, 1):
        items, st = read_packets(p, i[0], i[1])
        streams.append(items)
        rel = os.path.relpath(p, folder)
        print(f"   {k:>3}  {st['records']:>8}  {st['bytes']:>11}  {fmt(st['first']):19}  {fmt(st['last']):19}  {rel}")
        if st["zero"]:
            print(f"        [!] {st['zero']} khali (zero) record skip kiye (file ke end ka kachra, asli packet nahi)")
            warns.append(f"{st['zero']} zero-record skip: {rel}")
        if st["trunc_bytes"]:
            print(f"        [!] file adhoori: end ke {st['trunc_bytes']} bytes padhe nahi ja sake (source file hi damaged)")
            warns.append(f"{st['trunc_bytes']} bytes truncated tail in source: {rel}")
        if st["reordered"]:
            print("        (file ke andar packets out-of-order the, time se sort kiye)")
        in_pk += st["records"]; in_by += st["bytes"]; in_fp = (in_fp + st["fp"]) & M64
        zero_total += st["zero"]; trunc_total += st["trunc_bytes"]
        if st["first"]:
            in_first = min(in_first or st["first"], st["first"])
            in_last = max(in_last, st["last"])
        details.append([date, hp, rel, st["size"], st["records"], st["bytes"], st["zero"],
                        st["trunc_bytes"], fmt(st["first"]), fmt(st["last"])])
    for d, orig in dups:
        print(f"   [i] duplicate file merge me NAHI li: {os.path.relpath(d, folder)}  (same as {os.path.relpath(orig, folder)})")
        warns.append(f"duplicate file skip: {os.path.relpath(d, folder)}")

    # ---- 2) MERGE ----
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "wb") as out:
        out.write(struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, snaplen, link))
        for ts, orig, data in heapq.merge(*streams, key=lambda x: x[0]):
            out.write(struct.pack("<IIII", ts // 10**9, ts % 10**9, len(data), orig))
            out.write(data)
    del streams

    # ---- 3) VERIFY (output ko dobara padho) ----
    o_pk, o_by, o_fp, o_first, o_last = verify_output(out_path)
    ok = (o_pk == in_pk and o_by == in_by and o_fp == in_fp)
    status = "PASS" if ok else "FAIL"
    print(f"\n   OUTPUT: {out_path}")
    print(f"   Time range : {fmt(o_first)}  ->  {fmt(o_last)}")
    print(f"   Packets    : input {in_pk}  |  output {o_pk}  |  difference {in_pk - o_pk}")
    print(f"   Data bytes : input {in_by}  |  output {o_by}")
    print(f"   Content    : fingerprint {'MATCH' if o_fp == in_fp else 'MISMATCH'}")
    print(f"   RESULT     : {status}" + ("  -> koi data loss nahi" if ok else "  -> DATA MISMATCH! output par bharosa mat karo"))
    if warns:
        print("   NOTES      : " + f"{zero_total} zero-record skip, {trunc_total} truncated bytes, {len(dups)} duplicate file(s)")
    print()
    summary.append([date, hp, len(files), in_pk, o_pk, in_pk - o_pk, in_by, o_by,
                    "MATCH" if o_fp == in_fp else "MISMATCH", status, "; ".join(warns)])


def upsert_csv(path, header, new_rows, key_n=2):
    """Purani CSV ki rows rakhta hai; sirf wahi (date, honeypot) rows badalta hai jo is run me dobara bani."""
    old = []
    if os.path.exists(path):
        try:
            with open(path, newline="", encoding="utf-8") as f:
                r = csv.reader(f)
                next(r, None)
                for row in r:
                    if row:
                        old.append((row + [""] * len(header))[:len(header)])
        except OSError:
            pass
    new_rows = [[str(x) for x in r] for r in new_rows]
    new_keys = {tuple(r[:key_n]) for r in new_rows}
    rows = [r for r in old if tuple(r[:key_n]) not in new_keys] + new_rows
    rows.sort(key=lambda r: (int(r[0]) if r[0].isdigit() else 999, r[1]))  # stable: date, honeypot
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(header)
            w.writerows(rows)
        return path
    except PermissionError:  # file Excel me khuli ho to
        alt = path.replace(".csv", "_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + ".csv")
        with open(alt, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(header)
            w.writerows(rows)
        print(f"[!] {os.path.basename(path)} Excel me khuli hai, isliye nayi file me save hua: {alt}")
        return alt


def hp_name(x):
    return f"cdac_hp_{x}" if x.isdigit() else x


def discover_hps(date_dir):
    names = set()
    for dp, dirs, _ in os.walk(date_dir):
        names.update(d for d in dirs if HP_RE.match(d))
    return sorted(names, key=lambda s: int(s.rsplit("_", 1)[1]))


def main():
    ap = argparse.ArgumentParser(description="Date + honeypot wise pcap merger with verification")
    ap.add_argument("root", help="main folder jisme 10, 18, 25... date folders hain")
    ap.add_argument("--date", nargs="*", help="e.g. --date 10 18")
    ap.add_argument("--hp", nargs="*", help="1  ya  1 3  ya  all")
    ap.add_argument("--out", help="output folder (default: ROOT\\merged_output)")
    a = ap.parse_args()

    root = os.path.abspath(a.root)
    out_dir = a.out or os.path.join(root, "merged_output")
    if not os.path.isdir(root):
        sys.exit(f"Folder nahi mila: {root}")
    dates = sorted(d for d in os.listdir(root)
                   if os.path.isdir(os.path.join(root, d)) and d != "merged_output"
                   and os.path.abspath(os.path.join(root, d)) != os.path.abspath(out_dir))
    if a.date:
        bad = [d for d in a.date if d not in dates]
        if bad:
            sys.exit(f"Ye date folder nahi mile: {bad}. Available: {dates}")
        dates = a.date

    print(f"Root  : {root}\nDates : {dates}\nHP    : {a.hp or 'sabhi (ek file me mix)'}\nOutput: {out_dir}\n")
    summary, details = [], []
    for d in dates:
        ddir = os.path.join(root, d)
        if not a.hp:
            print("=" * 100 + f"\n[date {d}]")
            merge(d, "all", ddir, os.path.join(out_dir, f"{d}.pcap"), None, summary, details)
            continue
        hps = discover_hps(ddir) if [x.lower() for x in a.hp] == ["all"] else [hp_name(x) for x in a.hp]
        for hp in hps:
            print("=" * 100 + f"\n[date {d} | {hp}]")
            merge(d, hp, ddir, os.path.join(out_dir, f"{d}_{hp}.pcap"), hp, summary, details)

    # ---- reports (purani rows ke saath jud jati hain, overwrite nahi hoti) ----
    os.makedirs(out_dir, exist_ok=True)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sum_path = upsert_csv(
        os.path.join(out_dir, "verification_summary.csv"),
        ["date", "honeypot", "input_files", "input_packets", "output_packets", "difference",
         "input_bytes", "output_bytes", "content_fingerprint", "status", "notes", "run_time"],
        [r + [now] for r in summary])
    det_path = upsert_csv(
        os.path.join(out_dir, "verification_details.csv"),
        ["date", "honeypot", "input_file", "file_size", "packets", "data_bytes",
         "zero_records_skipped", "truncated_bytes", "first_packet", "last_packet", "run_time"],
        [r + [now] for r in details])

    print("=" * 100 + "\nFINAL SUMMARY")
    print(f"{'date':6} {'honeypot':11} {'files':>5} {'input pkts':>11} {'output pkts':>12} {'diff':>6}  status")
    for r in summary:
        print(f"{r[0]:6} {r[1]:11} {r[2]:>5} {r[3]:>11} {r[4]:>12} {r[5]:>6}  {r[9]}")
    bad = [r for r in summary if r[9] not in ("PASS",)]
    print("\nOVERALL: " + ("sab PASS - koi data loss nahi" if not bad else f"{len(bad)} output me problem, upar dekho"))
    print(f"Reports: {sum_path}\n         {det_path}")


if __name__ == "__main__":
    main()
