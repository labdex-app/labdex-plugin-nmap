"""nmap TCP connect scan of inventory networks, results into Discovery."""
import ipaddress
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

from labdex.plugins.base import Plugin as Base, PluginError

PORTS_RE = re.compile(r"^(top:\d{1,5}|[0-9,\-]+)$")


class Plugin(Base):
    def _targets(self):
        nets = {n["name"]: n for n in self.ctx.inventory.networks()}
        v4 = {n: [ipaddress.ip_network(p["prefix"]) for p in v.get("prefixes") or [] if p.get("family") == 4 and p.get("prefix")]
              for n, v in nets.items()}
        chosen = self.settings.get("networks") or [n for n, ps in v4.items() if ps]
        prefixes = [p for ps in v4.values() for p in ps]
        targets = []
        for name in chosen:
            if name not in nets:
                raise PluginError(f"unknown network '{name}'")
            targets += v4[name]  # every IPv4 prefix of the network
        for raw in self.settings.get("extra_targets") or []:
            try:
                t = ipaddress.ip_network(raw, strict=False)
            except ValueError as exc:
                raise PluginError(f"bad extra target {raw!r}: {exc}") from exc
            if t.version != 4 or not any(t.subnet_of(p) for p in prefixes):
                raise PluginError(f"{raw} isn't inside an inventory network; labdex only scans its own address space")
            targets.append(t)
        excluded = []
        for raw in self.settings.get("exclude") or []:
            try:
                excluded.append(ipaddress.ip_network(raw, strict=False))
            except ValueError as exc:
                raise PluginError(f"bad exclude {raw!r}: {exc}") from exc
        targets = list(ipaddress.collapse_addresses(targets))
        total = sum(t.num_addresses for t in targets)
        if not targets and not self.settings.get("ipv6", True):
            raise PluginError("nothing to scan: no networks with an IPv4 prefix selected")
        if total > int(self.settings.get("max_hosts") or 2048):
            raise PluginError(f"{total} addresses to scan exceeds the limit of {self.settings.get('max_hosts')}")
        return targets, excluded

    def widget_ports(self, host):
        return _widget_ports(host)

    def run_scan(self, params):
        exe = shutil.which("nmap")
        if exe is None:
            raise PluginError("nmap isn't installed in this labdex instance")
        targets, excluded = self._targets()
        ports = (self.settings.get("ports") or "top:200").replace(" ", "")
        if not PORTS_RE.match(ports):
            raise PluginError(f"bad port spec {ports!r}")
        timing = self.settings.get("timing") or "T3"
        if timing not in ("T2", "T3", "T4"):
            raise PluginError("timing must be T2, T3 or T4")
        common = [exe, "-sT", "--open", "-oX", "-", f"-{timing}", "--host-timeout", "300s"]
        if self.settings.get("service_detection", True):
            common += ["-sV", "--version-light"]
        base = common + (["--top-ports", ports[4:]] if ports.startswith("top:") else ["-p", ports])
        hosts, scanned = [], set()
        if targets:
            cmd = base + (["--exclude", ",".join(str(e) for e in excluded if e.version == 4)] if any(e.version == 4 for e in excluded) else [])
            hosts += self._nmap(cmd + [str(t) for t in targets])
            scanned |= {str(a) for t in targets for a in (t if t.num_addresses == 1 else t.hosts())}
            for e in excluded:
                scanned -= {str(a) for a in e}
        if self.settings.get("ipv6", True):
            v6 = self._ipv6_targets(excluded)
            if v6:
                self.log(f"IPv6: {len(v6)} known address(es)")
                hosts += self._nmap(base + ["-6"] + v6)
                scanned |= set(v6)
        probed = {}
        if self.settings.get("service_ports", True):
            # every declared TCP service is checked on its host's addresses, also ports outside the list above
            want = self._declared(scanned)
            if want:
                spec = ",".join(str(p) for p in sorted({p for ps in want.values() for p in ps}))
                self.log(f"declared services: {len(want)} address(es), port(s) {spec}")
                v4, v6 = [a for a in want if ":" not in a], [a for a in want if ":" in a]
                if v4:
                    hosts += self._nmap(common + ["-p", spec] + v4)
                if v6:
                    hosts += self._nmap(common + ["-6", "-p", spec] + v6)
                probed = {ip: [[p, "tcp"] for p in sorted(ps)] for ip, ps in want.items()}
        # MACs come from the firewall's ARP/NDP tables and DHCP leases: what nmap (or the machine it
        # runs on, often behind a container bridge) sees is the next router's MAC, not the host's.
        for h in hosts:
            h.pop("mac", None)
            h.pop("vendor", None)
        stats = self.ctx.discovery.record_scan(f"nmap:{self.ctx.name}", scanned, hosts, probed=probed)
        self.log(f"{stats['hosts_up']} host(s) with open ports, {stats['open_ports']} open port(s), {stats['closed']} newly closed")
        return stats

    def _nmap(self, cmd) -> list[dict]:
        """Run nmap with its normal output streamed into the job log (open ports as they're found,
        progress every 15 s) and the XML written to a file for parsing."""
        import os
        import tempfile
        import time
        fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="labdex-nmap-")
        os.close(fd)
        try:
            cmd = [c for c in cmd if c not in ("-oX", "-")]  # XML goes to the file, the log gets the readable output
            cmd = cmd[:1] + ["-oX", xml_path, "-v", "--stats-every", "15s"] + cmd[1:]
            self.log("$ " + " ".join(c for c in cmd[1:] if c != xml_path))
            deadline = time.monotonic() + int(self.settings.get("timeout") or 1800)
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            tail = []
            for line in proc.stdout:
                line = line.rstrip()
                tail = (tail + [line])[-20:]
                if _interesting(line):
                    self.log(line)
                if time.monotonic() > deadline:
                    proc.kill()
                    raise PluginError("scan timed out")
            rc = proc.wait()
            if rc != 0:
                raise PluginError(f"nmap exited {rc}: {' / '.join(tail[-3:])[:500]}")
            with open(xml_path, encoding="utf-8", errors="replace") as f:
                hosts = parse(f.read())
            for h in hosts:
                svcs = ", ".join(f"{x['port']}/{x['proto']} {x.get('service') or ''}".strip() for x in h.get("services", []))
                self.log(f"{h['ip']}{' (' + h['hostname'] + ')' if h.get('hostname') else ''}: {svcs or 'no open ports'}")
            return hosts
        finally:
            try:
                os.unlink(xml_path)
            except OSError:
                pass

    def _declared(self, scanned: set[str]) -> dict[str, set[int]]:
        """{address: {port}}: the TCP ports of declared services, on their host's addresses this scan covers."""
        out: dict[str, set[int]] = {}
        for h in self.ctx.inventory.hosts():
            ports = {int(sv["port"]) for sv in h.get("services") or [] if sv.get("port") and (sv.get("proto") or "tcp") == "tcp"}
            if not ports:
                continue
            for i in h["interfaces"]:
                for a in [i.get("ip4"), *(i.get("ip6_all") or [])]:
                    if a and a in scanned:
                        out.setdefault(a, set()).update(ports)
        return out

    def _ipv6_targets(self, excluded) -> list[str]:
        """Known IPv6 addresses inside the chosen networks' IPv6 prefixes: the inventory's and Discovery's."""
        from labdex.models import DiscoveredHost, db
        nets = {n["name"]: n for n in self.ctx.inventory.networks()}
        chosen = self.settings.get("networks") or list(nets)
        prefixes = [ipaddress.ip_network(p["prefix"]) for name in chosen if name in nets
                    for p in nets[name].get("prefixes") or [] if p.get("family") == 6 and p.get("prefix")]
        if not prefixes:
            return []
        found = {a for h in self.ctx.inventory.hosts() for i in h["interfaces"] for a in i.get("ip6_all") or []}
        found |= {d.ip for d in db.session.scalars(db.select(DiscoveredHost)) if ":" in d.ip}
        out = []
        for a in sorted(found):
            ip = ipaddress.ip_address(a)
            if any(ip in p for p in prefixes) and not any(ip.version == e.version and ip in e for e in excluded):
                out.append(a)
        limit = int(self.settings.get("max_hosts") or 2048)
        if len(out) > limit:
            raise PluginError(f"{len(out)} IPv6 addresses to scan exceeds the limit of {limit}")
        return out


def _widget_ports(host: dict) -> dict:
    from labdex.models import DiscoveredService, Host, db
    h = db.session.scalar(db.select(Host).where(Host.name == host["name"]))
    addrs = {a for i in h.interfaces for a in i.all_addresses if a} if h else set()
    if not addrs:
        return {"kind": "list", "items": [], "sub": "no addresses to scan"}
    declared = {(s.port, s.proto or "tcp"): s.name for s in h.services}
    rows = db.session.scalars(db.select(DiscoveredService).where(DiscoveredService.ip.in_(addrs), DiscoveredService.state == "open")
                              .order_by(DiscoveredService.port))
    seen, items = set(), []
    for ds in rows:
        if (ds.port, ds.proto) in seen:
            continue
        seen.add((ds.port, ds.proto))
        name = declared.get((ds.port, ds.proto))
        items.append({"label": f"{ds.port}/{ds.proto}", "value": name or " ".join(x for x in (ds.service, ds.product) if x) or "?",
                      "tone": "ok" if name else "warn"})
    undocumented = sum(1 for i in items if i["tone"] == "warn")
    return {"kind": "list", "items": items, "link": "/discovery",
            "sub": f"{undocumented} not documented as a service" if undocumented else "all documented" if items else "nothing open seen"}


def _interesting(line: str) -> bool:
    """Lines of nmap's normal output worth a place in the job log."""
    return line.startswith(("Discovered open port", "Stats:", "About ", "Nmap scan report", "Scanning ", "Initiating ",
                            "Completed ", "Service scan Timing", "Nmap done", "Warning:", "WARNING:")) or "% done" in line


def parse(xml_text: str) -> list[dict]:
    root = ET.fromstring(xml_text)
    out = []
    for h in root.findall("host"):
        status = h.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addr = next((a.get("addr") for a in h.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if not addr:
            continue
        mac_el = next((a for a in h.findall("address") if a.get("addrtype") == "mac"), None)  # only when nmap runs as root on the segment
        hn = h.find("hostnames/hostname")
        services = []
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            sv = p.find("service")
            services.append({
                "port": int(p.get("portid")), "proto": p.get("protocol", "tcp"),
                "service": sv.get("name", "") if sv is not None else "",
                "product": sv.get("product", "") if sv is not None else "",
                "version": " ".join(x for x in ((sv.get("version", "") if sv is not None else ""),
                                                (sv.get("extrainfo", "") if sv is not None else "")) if x),
            })
        out.append({"ip": addr, "hostname": hn.get("name", "") if hn is not None else "", "services": services,
                    "mac": mac_el.get("addr", "") if mac_el is not None else "", "vendor": mac_el.get("vendor", "") if mac_el is not None else ""})
    return out
