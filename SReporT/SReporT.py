#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#__version__ = "1.0"
#__author__ = "Onur Muhammet AKÇAY"

from __future__ import annotations
import argparse
import html
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple
from xml.etree import ElementTree as ET

VAR_SABLON = "template.html"
VAR_CIKTI = "sonuc.html"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("SReporT")

@dataclass
class Port:
    numara: str
    protokol: str = "tcp"
    durum: str = ""
    servis: str = ""
    urun: str = ""
    surum: str = ""
    scriptler: List[Tuple[str, str]] = field(default_factory=list)

@dataclass
class Host:
    ip: str
    host_adi: str = ""
    portlar: List[Port] = field(default_factory=list)
    isletim_sistemi: str = ""

def safe(s: Optional[str]) -> str:
    return html.escape(s or "")

def file_must_exist(p: Path, desc: str) -> None:
    if not p.exists():
        logger.error("%s bulunamadı: %s", desc, p)
        print(f" {desc} bulunamadı: {p}")
        sys.exit(1)

class NmapParser:
    @staticmethod
    def format_tespit(dosya: Path) -> str:
        sfx = dosya.suffix.lower()
        if sfx == ".xml":
            return "xml"
        if sfx == ".gnmap":
            return "gnmap"
        if sfx in {".txt", ".nmap"}:
            return "normal"
        try:
            with dosya.open("r", encoding="utf-8", errors="ignore") as f:
                parcacik = f.read(4096)
            if "<nmaprun" in parcacik:
                return "xml"
            if "Host:" in parcacik and "Ports:" in parcacik:
                return "gnmap"
        except Exception:
            pass
        return "normal"

    @staticmethod
    def xml_coz(dosya: Path) -> List[Host]:
        hostlar: List[Host] = []
        try:
            for _, host_elem in ET.iterparse(str(dosya), events=("end",)):
                if host_elem.tag != "host":
                    continue
                ip, host_adi, os_bilgi = "", "", ""
                portlar: List[Port] = []
                for addr in host_elem.findall(".//address"):
                    if addr.get("addrtype") == "ipv4":
                        ip = addr.get("addr", "") or ip
                if not ip:
                    host_elem.clear()
                    continue
                hn = host_elem.find(".//hostnames/hostname")
                if hn is not None:
                    host_adi = hn.get("name", "") or ""
                os_match = host_elem.find(".//os/osmatch")
                if os_match is not None:
                    os_bilgi = os_match.get("name", "") or ""
                if not os_bilgi:
                    os_bilgi = "Bilinmiyor"
                for p in host_elem.findall(".//ports/port"):
                    port = Port(numara=p.get("portid", "") or "")
                    port.protokol = p.get("protocol", "tcp") or "tcp"
                    st = p.find("state")
                    if st is not None:
                        port.durum = st.get("state", "") or ""
                    svc = p.find("service")
                    if svc is not None:
                        port.servis = svc.get("name", "") or ""
                        port.urun = svc.get("product", "") or ""
                        port.surum = svc.get("version", "") or ""
                    for s in p.findall("script"):
                        port.scriptler.append((
                            s.get("id", "") or "",
                            s.get("output", "") or ""
                        ))
                    portlar.append(port)
                hostlar.append(Host(ip=ip, host_adi=host_adi or "Bilinmiyor", portlar=portlar, isletim_sistemi=os_bilgi))
                host_elem.clear()
        except Exception as e:
            logger.error("XML ayrıştırma hatası: %s", e)
            print(f" XML ayrıştırma hatası: {e}")
        return hostlar

    @staticmethod
    def gnmap_coz(dosya: Path) -> List[Host]:
        hostlar: List[Host] = []
        try:
            with dosya.open("r", encoding="utf-8", errors="ignore") as f:
                for satir in f:
                    satir = satir.strip()
                    if not satir.startswith("Host:"):
                        continue
                    ip_parca = re.search(r"Host:\s+(\S+)\s+\(([^)]*)\)", satir)
                    if not ip_parca:
                        continue
                    ip = ip_parca.group(1)
                    host_adi = ip_parca.group(2) or "Bilinmiyor"
                    host = Host(ip=ip, host_adi=host_adi)
                    ports_part = re.search(r"Ports:\s+(.+)$", satir)
                    if ports_part:
                        ports_raw = ports_part.group(1)
                        for seg in ports_raw.split(","):
                            seg = seg.strip()
                            if not seg:
                                continue
                            parts = seg.split("/")
                            if len(parts) >= 5:
                                num = parts[0]
                                state = parts[1]
                                proto = parts[2]
                                svc = parts[4] or ""
                                host.portlar.append(Port(numara=num, protokol=proto, durum=state, servis=svc))
                    hostlar.append(host)
        except Exception as e:
            logger.error("GNMAP ayrıştırma hatası: %s", e)
            print(f" GNMAP ayrıştırma hatası: {e}")
        return hostlar

    @staticmethod
    def normal_coz(dosya: Path) -> List[Host]:
        hostlar: List[Host] = []
        try:
            text = dosya.read_text(encoding="utf-8", errors="ignore")
            sections = re.split(r"\nNmap scan report for\s+", text)
            for sec in sections:
                sec = sec.strip()
                if not sec:
                    continue
                lines = sec.splitlines()
                first = lines[0]
                ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", first)
                if not ip_match:
                    continue
                ip = ip_match.group(1)
                host_adi = "Bilinmiyor"
                hm = re.match(r"(.+?)\s+\(\d+\.\d+\.\d+\.\d+\)", first)
                if hm:
                    host_adi = hm.group(1).strip() or "Bilinmiyor"
                os_info = "Bilinmiyor"
                host = Host(ip=ip, host_adi=host_adi)
                in_table = False
                for ln in lines[1:]:
                    ln = ln.rstrip()
                    if ln.startswith("OS details:"):
                        m = re.search(r"OS details:\s+(.+)", ln)
                        if m:
                            os_info = m.group(1).strip() or "Bilinmiyor"
                        continue
                    if "PORT" in ln and "STATE" in ln and "SERVICE" in ln:
                        in_table = True
                        continue
                    if in_table:
                        if not ln or ln.startswith("MAC Address") or ln.startswith("Device type"):
                            in_table = False
                            continue
                        parts = ln.split(None, 2)
                        if len(parts) >= 2:
                            port_field = parts[0]
                            state = parts[1]
                            service = parts[2] if len(parts) > 2 else ""
                            if "/" in port_field:
                                number, proto = port_field.split("/", 1)
                            else:
                                number, proto = port_field, "tcp"
                            svc_name = service.split()[0] if service else ""
                            host.portlar.append(Port(numara=number, protokol=proto, durum=state, servis=svc_name))
                host.isletim_sistemi = os_info
                if host.portlar or os_info:
                    hostlar.append(host)
        except Exception as e:
            logger.error("Normal format ayrıştırma hatası: %s", e)
            print(f" Normal format ayrıştırma hatası: {e}")
        return hostlar

class RaporUretici:
    def __init__(self, sablon_yolu: Path):
        self.sablon_yolu = sablon_yolu
        self.sablon = self._sablon_yukle()

    def _sablon_yukle(self) -> str:
        return self.sablon_yolu.read_text(encoding="utf-8")

    def rapor_uret(self, hostlar: List[Host], cikti: Path) -> None:
        satirlar: List[str] = [self._satir_olustur(h) for h in hostlar]
        if not satirlar:
            satirlar.append(
                '<tr><td colspan="5" class="empty-state">Tarama sonucu boş veya desteklenmeyen format.</td></tr>'
            )
        html_out = self.sablon
        tbody_pattern = r'(<tbody[^>]*id="vulnerabilityTableBody"[^>]*>)(.*?)(</tbody>)'
        html_out = re.sub(
            tbody_pattern,
            lambda m: m.group(1) + "\n" + "\n".join(satirlar) + "\n" + m.group(3),
            html_out,
            flags=re.S
        )

        # İstatistikleri Python tarafında hesapla
        toplam_host = len(hostlar)
        toplam_port = sum(len(h.portlar) for h in hostlar)
        toplam_servis = sum(1 for h in hostlar for p in h.portlar if p.servis)
        toplam_script = sum(len(p.scriptler) for h in hostlar for p in h.portlar)

        html_out = html_out.replace('id="totalHosts">0', f'id="totalHosts">{toplam_host}')
        html_out = html_out.replace('id="totalPorts">0', f'id="totalPorts">{toplam_port}')
        html_out = html_out.replace('id="totalServices">0', f'id="totalServices">{toplam_servis}')
        html_out = html_out.replace('id="totalScripts">0', f'id="totalScripts">{toplam_script}')

        script_satirlari = []
        for h in hostlar:
            for p in h.portlar:
                for sid, sout in p.scriptler:
                    script_satirlari.append(f"""
<tr>
  <td>{safe(h.host_adi)}</td>
  <td>{safe(h.ip)}</td>
  <td>{safe(p.numara)}/{safe(p.protokol)}</td>
  <td><span class="chip">{safe(sid)}</span></td>
  <td>{safe(sout)}</td>
</tr>""")
        script_html = ""
        if script_satirlari:
            script_html = f"""
<h2>Script Sonuçları</h2>
<div class="table-wrap">
<table>
  <thead>
    <tr>
      <th>Host Adı</th>
      <th>IP</th>
      <th>Port</th>
      <th>Script</th>
      <th>Çıktı</th>
    </tr>
  </thead>
  <tbody>
    {''.join(script_satirlari)}
  </tbody>
</table>
</div>
"""
        html_out = html_out.replace('<div id="scriptSection"></div>', script_html)
        tarih = time.strftime("%d/%m/%Y %H:%M:%S", time.localtime())
        html_out = html_out.replace(
            '<p id="createdDate"></p>',
            f'<p id="createdDate">Rapor oluşturulma tarihi: {safe(tarih)}</p>'
        )
        cikti.write_text(html_out, encoding="utf-8")
        print(f" Rapor oluşturuldu: {cikti}")
        print(f" - Toplam Host: {toplam_host}")
        print(f" - Toplam Port: {toplam_port}")
        print(f" - Toplam Servis: {toplam_servis}")
        print(f" - Toplam Script Çıktısı: {toplam_script}")

    def _satir_olustur(self, host: Host) -> str:
        hostname_cell = f'<span class="chip">{safe(host.host_adi)}</span>' if host.host_adi else "&nbsp;"
        ip_cell = f'<span class="chip">{safe(host.ip)}</span>'
        port_chipleri = []
        for p in host.portlar:
            pstr = f"{p.numara}/{p.protokol}"
            if p.durum and p.durum != "open":
                pstr += f" ({p.durum})"
            port_chipleri.append(f'<span class="chip">{safe(pstr)}</span>')
        ports_cell = " ".join(port_chipleri) if port_chipleri else "&nbsp;"
        svc_chipleri = []
        for p in host.portlar:
            svc = p.servis or "bilinmiyor"
            if p.surum:
                svc += f" {p.surum}"
            svc_chipleri.append(f'<span class="chip">{safe(svc)}</span>')
        services_cell = " ".join(svc_chipleri) if svc_chipleri else "&nbsp;"
        os_cell = f'<span class="chip">{safe(host.isletim_sistemi)}</span>' if host.isletim_sistemi else "<span class='chip'>Bilinmiyor</span>"
        return (
            "<tr>"
            f"<td>{hostname_cell}</td>"
            f"<td>{ip_cell}</td>"
            f"<td>{ports_cell}</td>"
            f"<td>{services_cell}</td>"
            f"<td>{os_cell}</td>"
            "</tr>"
        )

class ScanReportTool:
    def __init__(self):
        self.parser = NmapParser()

    def calistir(self, girdi: str, cikti: Optional[str] = None, sablon: Optional[str] = None) -> None:
        inp = Path(girdi)
        file_must_exist(inp, "Girdi dosyası")
        tmpl = Path(sablon) if sablon else Path(__file__).parent / VAR_SABLON
        file_must_exist(tmpl, "Şablon dosyası")
        outp = Path(cikti) if cikti else Path(VAR_CIKTI)
        fmt = self.parser.format_tespit(inp)
        print(f" Tespit edilen format: {fmt}")
        if fmt == "xml":
            hostlar = self.parser.xml_coz(inp)
        elif fmt == "gnmap":
            hostlar = self.parser.gnmap_coz(inp)
        else:
            hostlar = self.parser.normal_coz(inp)
        RaporUretici(tmpl).rapor_uret(hostlar, outp)

def main():
    ap = argparse.ArgumentParser(
        prog="SReporT",
        
    )
    ap.add_argument("-i", "--input", required=True, help="Nmap çıktı dosyası (.xml, .gnmap, .txt, .nmap)")
    ap.add_argument("-o", "--output", required=False, help="Çıktı HTML dosyası (varsayılan: sonuc.html)")
    ap.add_argument("-t", "--template", required=False, help="Şablon HTML dosyası (varsayılan: template.html)")
    args = ap.parse_args()
    try:
        ScanReportTool().calistir(args.input, args.output, args.template)
    except KeyboardInterrupt:
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as e:
        print(f" Beklenmeyen hata: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

