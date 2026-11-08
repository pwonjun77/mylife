import io
import json
import sys
import unittest
import urllib.error
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sbom_inventory.collectors import agent_import, graph, nmap_scan  # noqa: E402
from sbom_inventory.export import cyclonedx  # noqa: E402
from sbom_inventory.models import Asset, Component, HostRecord, cpe22_to_23, norm_mac, norm_name, version_lt  # noqa: E402
from sbom_inventory.policy import check, load_policy  # noqa: E402
from sbom_inventory.store import Store  # noqa: E402

FIX = ROOT / "tests" / "fixtures"
EX = ROOT / "examples"


class ModelTests(unittest.TestCase):
    def test_version_compare(self):
        self.assertTrue(version_lt("1.9.9", "1.10.0"))
        self.assertTrue(version_lt("129.0.6668.90", "131.0.6778.85"))
        self.assertFalse(version_lt("2.0", "2.0.0"))
        self.assertTrue(version_lt("1.0rc1", "1.0"))
        self.assertTrue(version_lt("8.2p1", "9.8"))

    def test_normalize(self):
        self.assertEqual(norm_mac("AA-BB-CC-00-00-21"), "aa:bb:cc:00:00:21")
        self.assertEqual(norm_mac("00:00:00:00:00:00"), "")
        self.assertEqual(norm_name("7-Zip 23.01 (x64)"), "7-zip 23.01")
        self.assertEqual(Asset(hostname="PC-021.corp.local").normalized().hostname, "pc-021")
        self.assertEqual(Asset(serial="To be filled by O.E.M.").normalized().serial, "")
        self.assertEqual(cpe22_to_23("cpe:/a:openbsd:openssh:8.2p1"), "cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*")


class NmapTests(unittest.TestCase):
    def test_parse(self):
        recs = nmap_scan.parse_nmap_xml(FIX / "nmap_sample.xml")
        self.assertEqual(len(recs), 2)  # down 호스트 제외
        pc = recs[0]
        self.assertEqual(pc.asset.hostname, "PC-021.corp.local")
        self.assertIn("os", {c.type for c in pc.components})
        nas = recs[1]
        ssh = next(c for c in nas.components if c.name == "OpenSSH")
        self.assertEqual(ssh.version, "8.2p1 Ubuntu 4ubuntu0.5")
        self.assertEqual(ssh.props["port"], "22/tcp")
        self.assertTrue(ssh.cpe.startswith("cpe:2.3:a:openbsd:openssh"))

    def test_target_validation_blocks_arg_injection(self):
        for bad in ["--script=evil", "-iL /etc/shadow", "10.0.0.1;id", "10.0.0.0/8"]:
            with self.assertRaises(ValueError):
                nmap_scan.validate_target(bad)
        cmd = nmap_scan.build_command(["10.0.0.0/24", "host-1.corp"], out_xml="x.xml")
        self.assertEqual(cmd[-2:], ["10.0.0.0/24", "host-1.corp"])

    def test_rejects_entities(self):
        p = Path(self.id() + ".xml")
        p.write_text('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><nmaprun/>')
        try:
            with self.assertRaises(ValueError):
                nmap_scan.parse_nmap_xml(p)
        finally:
            p.unlink()


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def fake_opener(routes):
    calls = []

    def opener(req, timeout=0):
        url = req.full_url
        calls.append(url)
        if "oauth2/v2.0/token" in url:
            return FakeResp(json.dumps({"access_token": "t", "expires_in": 3600}).encode())
        for k, v in routes.items():
            if k in url:
                if isinstance(v, Exception):
                    raise v
                return FakeResp(json.dumps(v).encode())
        raise AssertionError(f"unexpected url {url}")
    opener.calls = calls
    return opener


class GraphTests(unittest.TestCase):
    def test_intune_per_app_with_paging(self):
        dev = {"id": "d1", "deviceName": "PC-021", "serialNumber": "5CG1234XYZ", "operatingSystem": "Windows",
               "osVersion": "10.0.19045", "wiFiMacAddress": "aabbcc000021"}
        routes = {
            "managedDevices?$select": {"value": [dev]},
            "detectedApps?$top=50": {"value": [{"id": "a1", "displayName": "Google Chrome", "version": "129.0"}],
                                     "@odata.nextLink": "https://graph.microsoft.com/v1.0/next-apps"},
            "next-apps": {"value": [{"id": "a2", "displayName": "Zoom", "version": "6.1"}]},
            "detectedApps/a1/managedDevices": {"value": [{"id": "d1"}]},
            "detectedApps/a2/managedDevices": {"value": [{"id": "d1"}]},
        }
        op = fake_opener(routes)
        c = graph.ApiClient("tenant", "cid", "secret", graph.GRAPH, opener=op)
        recs = graph.collect_intune(c)
        self.assertEqual(len(recs), 1)
        self.assertEqual({x.name for x in recs[0].components}, {"Google Chrome", "Zoom"})
        self.assertNotIn("secret", repr(c))

    def test_auth_error(self):
        err = urllib.error.HTTPError("u", 401, "x", {}, io.BytesIO(b'{"error":"invalid_client"}'))

        def opener(req, timeout=0):
            raise err
        c = graph.ApiClient("t", "c", "s", graph.GRAPH, opener=opener)
        with self.assertRaises(graph.AuthError):
            c.token()


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.s = Store(":memory:")

    def test_correlation_and_history(self):
        # 1) nmap: IP + PTR + MAC
        r1 = self.s.begin_run("nmap")
        self.s.ingest(r1, nmap_scan.parse_nmap_xml(FIX / "nmap_sample.xml"))
        self.s.end_run(r1)
        # 2) agent: 같은 PC (hostname/MAC 공유) → 한 자산으로 병합
        r2 = self.s.begin_run("agent")
        recs, errs = agent_import.import_dir(EX / "agent-windows-sample.json")
        self.assertFalse(errs)
        self.s.ingest(r2, recs)
        self.s.end_run(r2)
        # 3) intune: serial 만 같고 이름은 대문자/FQDN 아님 → serial 로 병합
        r3 = self.s.begin_run("intune")
        self.s.ingest(r3, [HostRecord("intune", Asset(hostname="pc-021", serial="5cg1234xyz"),
                                      [Component("Google Chrome", "129.0.6668.90")])])
        self.s.end_run(r3)

        assets = self.s.assets()
        self.assertEqual(len(assets), 2)  # PC-021 + NAS(IP만)
        pc = self.s.asset("PC-021")
        self.assertEqual(set(json.loads(pc["sources"])), {"nmap", "agent", "intune"})
        self.assertEqual(pc["os"], "Microsoft Windows 10 Enterprise")  # agent OS 가 nmap 추정보다 우선

        # 4) agent 재수집: Chrome 업데이트, AnyDesk 삭제, 7-Zip 동일
        r4 = self.s.begin_run("agent")
        data = json.loads((EX / "agent-windows-sample.json").read_text())
        data["packages"][0]["version"] = "131.0.6778.86"
        data["packages"] = data["packages"][:2]
        self.s.ingest(r4, [agent_import.parse_agent_json(data)])
        self.s.end_run(r4)

        changes = {(c.name, c.kind) for c in self.s.diff(r3, r4)}
        self.assertIn(("google chrome", "changed"), changes)
        self.assertIn(("anydesk", "removed"), changes)
        self.assertNotIn(("7-zip 23.01", "changed"), changes)
        # nmap 은 r4 에서 재수집되지 않았지만 '현재 인벤토리'에는 남아 있어야 하고, 삭제로 보이면 안 됨
        self.assertTrue(any(r["source"] == "nmap" for r in self.s.inventory(r4)))
        self.assertFalse(any(c.source == "nmap" for c in self.s.diff(r3, r4)))

        hist = [(r["run_id"], r["version"]) for r in self.s.history("chrome") if r["name"] == "Google Chrome"]
        self.assertIn((r2, "129.0.6668.90"), hist)
        self.assertIn((r4, "131.0.6778.86"), hist)

        # 정책
        viol = check(self.s.inventory(r4), load_policy(EX / "policy.example.json"), today=date(2026, 11, 8))
        details = {(v.name, v.detail.split(" —")[0]) for v in viol}
        self.assertIn(("7-Zip 23.01 (x64)", "최소 버전 24.07 미만"), details)
        self.assertIn(("OpenSSH", "최소 버전 9.8 미만"), details)
        self.assertFalse(any(v.name == "Google Chrome" and v.source == "agent" for v in viol))  # 패치됨
        self.assertTrue(any(v.name == "Google Chrome" and v.source == "intune" for v in viol))  # intune 은 아직 구버전 보고
        self.assertTrue(any("EOL" in v.detail for v in viol))

        # CycloneDX
        bom = cyclonedx(self.s, r4)
        self.assertEqual(bom["specVersion"], "1.6")
        refs = [c["bom-ref"] for d in bom["components"] for c in d["components"]]
        self.assertEqual(len(refs), len(set(refs)))
        single = cyclonedx(self.s, r4, "PC-021")
        self.assertEqual(single["metadata"]["component"]["type"], "device")
        self.assertTrue(any(c.get("purl", "").startswith("pkg:generic/") for c in single["components"]))

    def test_agent_rejects_bad_schema(self):
        with self.assertRaises(ValueError):
            agent_import.parse_agent_json({"schema": "x", "host": {"hostname": "a"}})


if __name__ == "__main__":
    unittest.main()
