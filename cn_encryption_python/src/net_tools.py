
import subprocess, sys, platform, re, requests, time
from urllib.parse import urlparse

def normalize_target(target: str) -> str:
    """Accept full URLs or plain hosts/IPs and return a hostname/IP for traceroute."""
    t = (target or "").strip()
    if not t: return t
    if re.match(r"^[a-zA-Z]+://", t):
        p = urlparse(t)
    else:
        # allow strings like example.com:443/path too
        p = urlparse("//" + t)
    host = p.netloc or p.path or t
    # strip IPv6 brackets and port
    host = host.strip("[]")
    if ":" in host and not re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        host = host.split(":", 1)[0]
    return host

def run_traceroute(host_or_url: str, max_hops: int = 20, timeout_sec: int = 30):
    host = normalize_target(host_or_url)
    sys_plat = platform.system().lower()
    if "windows" in sys_plat:
        cmd = ["tracert", "-d", "-h", str(max_hops), host]   # -d: no DNS
        tool = "tracert"
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops), host]  # -n numeric
        tool = "traceroute"

    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout_sec, text=True, encoding="utf-8", errors="ignore")
    except Exception as e:
        return {"host": host, "tool": tool, "error": str(e), "raw": ""}

    hops = []
    if tool == "tracert":
        # e.g., "  1     2 ms     1 ms     1 ms  192.168.1.1"
        hop_re = re.compile(r"^\s*(\d+)\s+(?:(?:<\d+|\d+)\s*ms\s+){1,3}([\d\.*:]+)\s*$")
        for line in out.splitlines():
            m = hop_re.search(line)
            if m:
                hop = int(m.group(1)); ip = m.group(2)
                vals = [float(x) for x in re.findall(r"(\d+)\s*ms", line)]
                rtt = sum(vals)/len(vals) if vals else None
                hops.append({"hop": hop, "ip": ip, "rtt_ms": rtt})
    else:
        # e.g., " 1  192.168.1.1  1.123 ms  1.045 ms  1.002 ms"
        hop_re = re.compile(r"^\s*(\d+)\s+([\d\.*:]+)")
        for line in out.splitlines():
            m = hop_re.search(line)
            if m:
                hop = int(m.group(1)); ip = m.group(2)
                vals = [float(v) for v in re.findall(r"(\d+(?:\.\d+)?)\s*ms", line)]
                rtt = sum(vals)/len(vals) if vals else None
                hops.append({"hop": hop, "ip": ip, "rtt_ms": rtt})

    return {"host": host, "tool": tool, "hops": hops, "raw": out}

def geolocate_ip(ip: str, timeout=6.0):
    """Return dict with country, city, lat, lon, org using ip-api.com (no API key)."""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,org,query"
        r = requests.get(url, timeout=timeout)
        j = r.json()
        if j.get("status") == "success":
            return {
                "ip": j.get("query"), "country": j.get("country"),
                "city": j.get("city"), "lat": j.get("lat"), "lon": j.get("lon"),
                "org": j.get("org")
            }
    except Exception:
        pass
    return {"ip": ip, "country": None, "city": None, "lat": None, "lon": None, "org": None}

def enrich_hops_with_geo(hops):
    enriched = []
    for h in hops:
        ip = h.get("ip")
        info = geolocate_ip(ip) if ip and ip != "*" else {"ip": ip, "country": None, "city": None, "lat": None, "lon": None, "org": None}
        e = dict(h); e.update(info)
        enriched.append(e)
        time.sleep(0.15)  # be polite to the free API
    return enriched
