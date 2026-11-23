#!/usr/bin/env python3
"""Test chức năng apex_dns.h trên host: captive, forwarder không chặn, lọc nguồn upstream, gói lỗi."""
import os, socket, struct, subprocess, sys, tempfile, threading, time

DNS_PORT, UP_PORT = 15353, 15354
here = os.path.dirname(os.path.abspath(__file__))
binpath = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "dns_host")
flag = tempfile.mktemp()

def set_online(v):
    with open(flag, "w") as f: f.write("1" if v else "0")

def qname(n):
    return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\0"

def make_q(name, qtype=1, qid=0x1234, rd=1):
    return struct.pack(">HHHHHH", qid, 0x0100 if rd else 0, 1, 0, 0, 0) + qname(name) + struct.pack(">HH", qtype, 1)

def parse(resp):
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", resp[:12])
    ips = []
    if an:
        # question: skip name
        p = 12
        while resp[p] != 0: p += resp[p] + 1
        p += 5
        for _ in range(an):
            if resp[p] & 0xC0 == 0xC0: p += 2
            else:
                while resp[p] != 0: p += resp[p] + 1
                p += 1
            t, c, ttl, rl = struct.unpack(">HHIH", resp[p:p+10]); p += 10
            if t == 1 and rl == 4: ips.append(".".join(str(b) for b in resp[p:p+4]))
            p += rl
    return dict(id=qid, flags=flags, rcode=flags & 15, qd=qd, an=an, ips=ips, qr=flags >> 15, ra=(flags >> 7) & 1)

def ask(pkt, timeout=2.0, port=DNS_PORT):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    s.sendto(pkt, ("127.0.0.1", port))
    try:
        d, _ = s.recvfrom(2048)
        return d
    except socket.timeout:
        return None
    finally:
        s.close()

fails = 0
def check(cond, msg):
    global fails
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond: fails += 1

# ---------- fake upstream ----------
up_log = []
up_stop = False
def upstream():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", UP_PORT)); s.settimeout(0.2)
    while not up_stop:
        try: d, a = s.recvfrom(2048)
        except socket.timeout: continue
        qid = struct.unpack(">H", d[:2])[0]
        up_log.append((qid, a))
        p = 12; labels = []
        while d[p] != 0: labels.append(d[p+1:p+1+d[p]].decode()); p += d[p] + 1
        name = ".".join(labels)
        def reply(d=d, a=a, name=name):
            if name.startswith("slow."): time.sleep(1.0)
            if name.startswith("silent."): return
            end = 12; 
            while d[end] != 0: end += d[end] + 1
            end += 5
            r = bytearray(d[:end]); r[2] = 0x81; r[3] = 0x80; r[7] = 1
            r += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([9, 9, 9, 9])
            s.sendto(bytes(r), a)
        threading.Thread(target=reply, daemon=True).start()
    s.close()
threading.Thread(target=upstream, daemon=True).start()

set_online(False)
proc = subprocess.Popen([binpath, str(DNS_PORT), str(UP_PORT), flag], stderr=subprocess.PIPE)
time.sleep(0.4)
try:
    print("[offline / captive]")
    r = ask(make_q("connectivitycheck.gstatic.com", 1, 0xBEEF)); p = parse(r)
    check(p["id"] == 0xBEEF and p["qr"] == 1 and p["ra"] == 1, "ID giữ nguyên, QR=1, RA=1")
    check(p["qd"] == 1, "QDCOUNT=1 (bản cũ = 0)")
    check(p["rcode"] == 0 and p["ips"] == ["192.168.4.1"], "A -> 192.168.4.1")
    p = parse(ask(make_q("connectivitycheck.gstatic.com", 28)))
    check(p["rcode"] == 0 and p["an"] == 0 and p["qd"] == 1, "AAAA -> NOERROR rỗng (không trả A cho AAAA)")
    p = parse(ask(make_q("CaPtIvE.AppLe.com", 1)))
    check(p["ips"] == ["192.168.4.1"], "không phân biệt hoa/thường")
    p = parse(ask(make_q("sub.www.google.com", 1)))
    check(p["ips"] == ["192.168.4.1"], "subdomain thật sự khớp")
    p = parse(ask(make_q("evilwww.google.com", 1)))
    check(p["rcode"] == 2 and p["an"] == 0, "evilwww.google.com KHÔNG khớp (ranh giới nhãn) -> SERVFAIL")
    p = parse(ask(make_q("example.org", 1)))
    check(p["rcode"] == 2, "domain khác khi offline -> SERVFAIL")

    print("[gói lỗi / lạ]")
    for bad in [b"", b"\x00" * 5, os.urandom(11), os.urandom(300),
                make_q("a.b")[:-3], b"\x12\x34\x81\x80" + b"\x00" * 8,  # là response, không phải query
                struct.pack(">HHHHHH", 1, 0x2800, 1, 0, 0, 0) + qname("x.y") + b"\x00\x01\x00\x01",  # opcode != 0
                struct.pack(">HHHHHH", 1, 0x0100, 2, 0, 0, 0) + qname("x.y") + b"\x00\x01\x00\x01"]:  # QDCOUNT=2
        ask(bad, timeout=0.15)
    p = parse(ask(make_q("connectivitycheck.gstatic.com", 1)))
    check(p["ips"] == ["192.168.4.1"], "server vẫn sống sau khi nhận gói lỗi")

    print("[online / forwarder]")
    set_online(True)
    up_log.clear()
    r = ask(make_q("fast.test", 1, 0xABCD)); p = parse(r)
    check(p["id"] == 0xABCD and p["ips"] == ["9.9.9.9"], "forward + trả đúng ID gốc")
    check(len(up_log) == 1, "đã gửi đúng 1 truy vấn lên upstream")

    res = {}
    def client(name, qid):
        t0 = time.time(); r = ask(make_q(name, 1, qid), timeout=3.0)
        res[name] = (time.time() - t0, parse(r) if r else None)
    t1 = threading.Thread(target=client, args=("slow.test", 0x1111))
    t2 = threading.Thread(target=client, args=("fast.test", 0x2222))
    t1.start(); time.sleep(0.1); t2.start(); t1.join(); t2.join()
    check(res["fast.test"][0] < 0.5, "truy vấn nhanh không bị kẹt sau truy vấn chậm (%.2fs)" % res["fast.test"][0])
    check(res["slow.test"][0] >= 0.9 and res["slow.test"][1]["ips"] == ["9.9.9.9"], "truy vấn chậm vẫn được trả (%.2fs)" % res["slow.test"][0])
    check(res["fast.test"][1]["id"] == 0x2222 and res["slow.test"][1]["id"] == 0x1111, "mỗi client nhận đúng ID của mình")

    # Giả mạo: kẻ tấn công biết đúng ID + cổng socket upstream nhưng gửi từ cổng nguồn khác
    up_log.clear()
    spoof_res = {}
    def slow_client():
        spoof_res["r"] = ask(make_q("slow.test", 1, 0x5555), timeout=3.0)
    tc = threading.Thread(target=slow_client); tc.start()
    time.sleep(0.3)
    qid, srv_addr = up_log[-1]
    forged = bytearray(make_q("slow.test", 1, qid)); forged[2] = 0x81; forged[3] = 0x80; forged[7] = 1
    forged += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([6, 6, 6, 6])
    atk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); atk.sendto(bytes(forged), srv_addr); atk.close()
    tc.join()
    p = parse(spoof_res["r"])
    check(p["ips"] == ["9.9.9.9"] and p["id"] == 0x5555, "trả lời giả mạo từ cổng khác bị bỏ qua")

    # upstream im lặng: client không nhận gì (không crash), bảng pending tự dọn sau TTL
    check(ask(make_q("silent.test", 1), timeout=0.5) is None, "upstream im lặng -> không có trả lời giả")
    time.sleep(2.3)
    # làm đầy bảng pending bằng 12 truy vấn "silent" rồi kiểm tra vẫn phục hồi
    socks = []
    for i in range(12):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.3)
        s.sendto(make_q("silent.test", 1, 0x3000 + i), ("127.0.0.1", DNS_PORT)); socks.append(s)
    servfail = 0
    for s in socks:
        try:
            d, _ = s.recvfrom(2048)
            if parse(d)["rcode"] == 2: servfail += 1
        except socket.timeout: pass
        s.close()
    check(servfail >= 4, "bảng pending đầy -> SERVFAIL cho truy vấn dư (%d)" % servfail)
    time.sleep(2.3)
    p = parse(ask(make_q("fast.test", 1, 0x4444)))
    check(p["ips"] == ["9.9.9.9"], "phục hồi sau khi bảng pending hết hạn")

    print("[chuyển lại offline]")
    set_online(False)
    p = parse(ask(make_q("captive.apple.com", 1)))
    check(p["ips"] == ["192.168.4.1"], "offline lại -> spoof captive")
finally:
    up_stop = True
    proc.terminate()
    try: proc.wait(timeout=2)
    except Exception: proc.kill()
    err = proc.stderr.read().decode()
    check("exit 0" in err, "server thoát sạch khi nhận SIGTERM")

print("\nFAILED: %d" % fails if fails else "\nALL OK")
sys.exit(1 if fails else 0)
