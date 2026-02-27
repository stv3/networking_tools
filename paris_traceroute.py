#!/usr/bin/env python3
"""
Paris-style traceroute (UDP/TCP/ICMP) using Scapy.

Usage (like classic traceroute):
  sudo python3 paris_traceroute.py example.com              # UDP (default)
  sudo python3 paris_traceroute.py -I 1.1.1.1              # ICMP
  sudo python3 paris_traceroute.py -T -p 443 google.com     # TCP SYN to port 443
  sudo python3 paris_traceroute.py -m 20 -q 5 -w 1.5 8.8.8.8

Notes:
  - Paris behavior: keep flow identifiers stable for ECMP (UDP/TCP keep sport+dport constant).
  - Requires sudo (raw sockets).
"""

import argparse, os, random, socket, struct, time
from typing import Optional, Tuple
from scapy.all import IP, UDP, ICMP, TCP, Raw, sr1, conf  # type: ignore


def ms() -> float: return time.time() * 1000.0
def rsv4(h: str) -> str:
    try: return socket.gethostbyname(h)
    except socket.gaierror as e: raise SystemExit(f"resolve failed: {h}: {e}")


def classify(proto: str, ans) -> Tuple[Optional[str], bool]:
    if ans is None: return None, False
    ip = getattr(ans, "src", None)

    if ans.haslayer(ICMP):
        ic = ans.getlayer(ICMP)
        if ic.type == 11: return ip, False  # time exceeded
        if ic.type == 0:  return ip, True   # echo-reply (icmp reached)
        if ic.type == 3:  return ip, True   # dest unreachable (udp reached-ish)
        return ip, True                      # other ICMP indicates we hit something

    if proto == "tcp" and ans.haslayer(TCP):
        tc = ans.getlayer(TCP)
        f = int(tc.flags)
        if (f & 0x12) or (f & 0x04): return ip, True  # SYN/ACK or RST => reached host
        return ip, True

    return ip, True


def probe(proto: str, dst: str, ttl: int, sport: int, dport: int, icmp_id: int, plen: int):
    plen = max(plen, 12)
    payload = struct.pack("!I", 0x50524953) + os.urandom(plen - 4)  # 'PRIS' + pad
    ip = IP(dst=dst, ttl=ttl)
    if proto == "udp":  return ip / UDP(sport=sport, dport=dport) / Raw(load=payload)
    if proto == "tcp":  return ip / TCP(sport=sport, dport=dport, flags="S", seq=123456789) / Raw(load=payload)
    if proto == "icmp": return ip / ICMP(type=8, id=icmp_id, seq=1) / Raw(load=payload)
    raise ValueError(proto)


def run(dst: str, proto: str, dport: int, sport: int, mh: int, q: int, to: float, plen: int) -> int:
    conf.verb = 0
    print(f"paris-traceroute to {dst} ({dst}), {mh} hops max, {q} probes, proto={proto}")
    icmp_id = random.randint(0, 0xFFFF)

    for ttl in range(1, mh + 1):
        ips, rtts, reached = [], [], False

        for _ in range(q):
            t0 = ms()
            ans = sr1(probe(proto, dst, ttl, sport, dport, icmp_id, plen), timeout=to)
            ip, done = classify(proto, ans)
            ips.append(ip)
            rtts.append(None if ip is None else ms() - t0)
            reached |= done

        first = next((i for i in ips if i), None)
        line = f"{ttl:2d}  {first if first else '*'}"
        for ip, dt in zip(ips, rtts):
            if ip is None: line += "  *"
            else:
                if first and ip != first: line += f"  {ip}"
                line += f"  {dt:.1f} ms"
        print(line)
        if reached: return 0

    return 1


def main() -> int:
    p = argparse.ArgumentParser(
        prog="paris_traceroute.py",
        formatter_class=argparse.RawTextHelpFormatter,
        description=(
            "Paris-style traceroute (UDP/TCP/ICMP) using Scapy.\n"
            "Keeps flow identifiers stable to reduce ECMP-induced path variation.\n\n"
            "Examples:\n"
            "  sudo python3 paris_traceroute.py example.com\n"
            "  sudo python3 paris_traceroute.py -I 1.1.1.1\n"
            "  sudo python3 paris_traceroute.py -T -p 443 google.com\n"
        ),
    )
    g = p.add_mutually_exclusive_group()
    g.add_argument("-I", "--icmp", action="store_true", help="ICMP echo probes")
    g.add_argument("-T", "--tcp", action="store_true", help="TCP SYN probes")
    p.add_argument("host", help="Destination hostname or IPv4 address")
    p.add_argument("-m", "--max-hops", type=int, default=30, help="Max hops (default: 30)")
    p.add_argument("-q", "--queries", type=int, default=3, help="Probes per hop (default: 3)")
    p.add_argument("-w", "--wait", type=float, default=2.0, help="Timeout per probe seconds (default: 2.0)")
    p.add_argument("-p", "--port", type=int, default=33434, help="Destination port for UDP/TCP (default: 33434)")
    p.add_argument("-s", "--sport", type=int, default=54321, help="Source port for UDP/TCP (default: 54321)")
    p.add_argument("--payload-len", type=int, default=32, help="Probe payload length (default: 32)")
    a = p.parse_args()

    proto = "icmp" if a.icmp else "tcp" if a.tcp else "udp"
    return run(rsv4(a.host), proto, a.port, a.sport, a.max_hops, a.queries, a.wait, a.payload_len)


if __name__ == "__main__":
    raise SystemExit(main())

