"""
Patched.im — CVE Scanner Engine
Shared by both CLI and Web UI.
"""

import os, time, re, csv, json
from datetime import datetime, timezone
from collections import defaultdict

from docx import Document
from docx.shared import Pt, Cm, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

# ── CPE ──
CPE_MAP = {
    "microsoft edge":("microsoft","edge"),"google chrome":("google","chrome"),
    "mozilla firefox":("mozilla","firefox"),"firefox":("mozilla","firefox"),
    "safari":("apple","safari"),
    "microsoft office":("microsoft","office"),"microsoft word":("microsoft","word"),
    "microsoft excel":("microsoft","excel"),"microsoft outlook":("microsoft","outlook"),
    "microsoft powerpoint":("microsoft","powerpoint"),"microsoft teams":("microsoft","teams"),
    "microsoft onedrive":("microsoft","onedrive"),"microsoft onenote":("microsoft","onenote"),
    "visual studio code":("microsoft","visual_studio_code"),
    "git":("git-scm","git"),"node.js":("nodejs","node.js"),
    "python":("python","python"),"docker desktop":("docker","docker_desktop"),
    "7-zip":("7-zip","7-zip"),
    "vlc media player":("videolan","vlc_media_player"),"vlc":("videolan","vlc_media_player"),
    "adobe acrobat reader":("adobe","acrobat_reader_dc"),"adobe acrobat":("adobe","acrobat"),
    "adobe reader":("adobe","acrobat_reader_dc"),
    "zoom":("zoom","zoom"),"zoom workplace":("zoom","zoom"),
    "slack":("slack","slack"),"notion":("notion","notion"),
    "malwarebytes":("malwarebytes","malwarebytes"),
    "java":("oracle","jre"),"openjdk":("oracle","openjdk"),"xcode":("apple","xcode"),
}
WIN_BUILD = {
    "26100":("windows_11","24H2"),"22631":("windows_11","23H2"),
    "22621":("windows_11","22H2"),"22000":("windows_11","21H2"),
    "19045":("windows_10","22H2"),"19044":("windows_10","21H2"),
    "19043":("windows_10","21H1"),"19042":("windows_10","20H2"),
    "19041":("windows_10","2004"),
}
MAC_INT = {"26":"15","25":"14","24":"13","23":"12"}

def _norm(n):
    n=n.lower().strip(); n=re.sub(r'\s*\(.*?\)','',n)
    n=re.sub(r'\s*(x64|x86|arm64|64-bit|32-bit).*$','',n,flags=re.I)
    return re.sub(r'\s*v?\d+(\.\d+)*\s*$','',n).strip()

def _fwin(v):
    p=v.split("."); b=p[2] if len(p)>=3 else ""
    if b in WIN_BUILD:
        pr,vr=WIN_BUILD[b]; return f"Windows 11 {vr}" if "11" in pr else f"Windows 10 {vr}"
    return f"Windows ({v})"

def _cmac(v):
    c=re.sub(r'\s*\(.*?\)','',v).strip(); m=c.split(".")[0] if c else ""
    if m in MAC_INT: c=MAC_INT[m]+c[len(m):]
    return c

def _os_cpe(name,ver):
    k=name.lower().strip()
    if not ver or ver=="0.0.0.0": return None
    if k=="windows":
        p=ver.split("."); b=p[2] if len(p)>=3 else ""
        pr,vl=WIN_BUILD.get(b,("windows_10",ver))
        return f"cpe:2.3:o:microsoft:{pr}:{vl}:*:*:*:*:*:*:*"
    if k=="macos": return f"cpe:2.3:o:apple:macos:{_cmac(ver)}:*:*:*:*:*:*:*"
    if k=="ios": return f"cpe:2.3:o:apple:iphone_os:{re.sub(r's*\\(.*?\\)','',ver).strip()}:*:*:*:*:*:*:*"
    return None

def _app_cpe(name,ver):
    n=_norm(name)
    if n in CPE_MAP: v,p=CPE_MAP[n]; return f"cpe:2.3:a:{v}:{p}:{ver or '*'}:*:*:*:*:*:*:*"
    for k,(v,p) in CPE_MAP.items():
        if n.startswith(k): return f"cpe:2.3:a:{v}:{p}:{ver or '*'}:*:*:*:*:*:*:*"
    return None

# ── NVD ──
import urllib.request, zipfile, sqlite3, logging, shutil

def parse_version(v):
    t = [int(x) for x in re.findall(r'\d+', str(v))]
    while len(t) > 1 and t[-1] == 0: t.pop()
    return tuple(t)

def version_match(app_cpe, node):
    app_parts = app_cpe.split(":")
    while len(app_parts) < 13: app_parts.append("*")
    
    crit = node.get("criteria", "")
    crit_parts = crit.split(":")
    
    app_product = app_parts[4].lower()
    crit_product = crit_parts[4].lower() if len(crit_parts) > 4 else ""
    
    if app_product != crit_product:
        if crit_product.startswith(app_product + "_"):
            suffix = crit_product[len(app_product)+1:]
            if app_parts[5].lower() != suffix:
                return False
        else:
            return False

    v_app_str = app_parts[5]
    if v_app_str == "*":
        return True
        
    v_app = parse_version(v_app_str)
    v_crit_str = crit_parts[5] if len(crit_parts) > 5 else "*"
    
    if v_crit_str not in ("*", "-"):
        if parse_version(v_crit_str) == v_app:
            return True
        if not any(k in node for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")):
            return False

    if 'versionStartIncluding' in node and v_app < parse_version(node['versionStartIncluding']): return False
    if 'versionStartExcluding' in node and v_app <= parse_version(node['versionStartExcluding']): return False
    if 'versionEndIncluding' in node and v_app > parse_version(node['versionEndIncluding']): return False
    if 'versionEndExcluding' in node and v_app >= parse_version(node['versionEndExcluding']): return False
        
    return True

def sync_nvd_local_dataset(db_path="nvd.db"):
    url = "https://codeload.github.com/fkie-cad/nvd-json-data-feeds/zip/refs/heads/main"
    filename = "/tmp/nvd_feed.zip"
    
    if not os.path.exists(filename) or (time.time() - os.path.getmtime(filename)) > 86400:
        print("Downloading NVD feed (this may take a minute)...")
        try:
            # Stream with an explicit socket timeout — urlretrieve() has no
            # timeout param, so a stalled server could otherwise hang forever.
            with urllib.request.urlopen(url, timeout=60) as resp, open(filename, "wb") as fh:
                shutil.copyfileobj(resp, fh)
        except Exception as e:
            print(f"Failed to download NVD feed: {e}")
            return

    KNOWN_PREFIXES = set([f"cpe:2.3:a:{v}:{p}" for v,p in CPE_MAP.values()])
    KNOWN_PREFIXES.update(["cpe:2.3:o:microsoft:windows_11", "cpe:2.3:o:microsoft:windows_10", "cpe:2.3:o:apple:macos", "cpe:2.3:o:apple:iphone_os"])
    
    db = sqlite3.connect(db_path)
    db.execute("CREATE TABLE IF NOT EXISTS nvd_cves (cve_id TEXT, cpe_prefix TEXT, description TEXT, base_score REAL, severity TEXT, published TEXT, configurations TEXT, PRIMARY KEY(cve_id, cpe_prefix))")
    db.execute("DELETE FROM nvd_cves")
    
    try:
        zf = zipfile.ZipFile(filename)
    except Exception as e:
        print(f"Failed to open NVD zip: {e}")
        return

    rows = []
    for name in zf.namelist():
        if not name.endswith('.json'): continue
        data = json.loads(zf.read(name))
        confs = data.get('configurations', [])
        if not confs: continue
        
        matched_prefixes = set()
        for conf in confs:
            for node in conf.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    crit = match.get("criteria", "")
                    for p in KNOWN_PREFIXES:
                        if crit.startswith(p):
                            matched_prefixes.add(p)
                            
        if matched_prefixes:
            c = data.get("cve",{})
            desc = next((d["value"] for d in c.get("descriptions",[]) if d.get("lang")=="en"), "")
            score, sev = None, "UNKNOWN"
            for vk in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if vk in c.get("metrics",{}) and c["metrics"][vk]:
                    cd = c["metrics"][vk][0].get("cvssData",{}); score = cd.get("baseScore"); sev = cd.get("baseSeverity","UNKNOWN"); break
            
            for p in matched_prefixes:
                rows.append((c.get("id","?"), p, desc[:200], score, sev.upper(), c.get("published","")[:10] or "N/A", json.dumps(confs)))
                
        if len(rows) > 5000:
            db.executemany("INSERT OR REPLACE INTO nvd_cves VALUES (?,?,?,?,?,?,?)", rows)
            rows = []
            
    if rows:
        db.executemany("INSERT OR REPLACE INTO nvd_cves VALUES (?,?,?,?,?,?,?)", rows)
    db.commit()
    db.close()

def nvd_db_path():
    """Where the local NVD match cache lives (PAT-2307).

    In DASHBOARD_STATE_DIR when it is set: the systemd unit sets it on
    patched-prod-01, where the code tree is root-owned and read-only to the
    service, so the cache cannot be created or written next to this file.
    Otherwise next to this file, as before. Read at call time so a test can
    point it somewhere else."""
    state_dir = os.getenv("DASHBOARD_STATE_DIR", "").strip()
    return os.path.join(state_dir or os.path.dirname(__file__), "nvd.db")


def _scan(app_cpe, key, cache):
    if app_cpe in cache: return cache[app_cpe]

    parts = app_cpe.split(':')
    if len(parts) < 6: return []
    base_cpe = ":".join(parts[:5])

    db_path = nvd_db_path()
    if not os.path.exists(db_path):
        sync_nvd_local_dataset(db_path)
        
    out = []
    with sqlite3.connect(db_path) as db:
        rows = db.execute("SELECT cve_id, description, base_score, severity, published, configurations FROM nvd_cves WHERE cpe_prefix = ?", (base_cpe,)).fetchall()
        
    for row in rows:
        cve_id, desc, score, sev, pub, confs_json = row
        if score is None: continue
        confs = json.loads(confs_json)
        matched = False
        
        for conf in confs:
            for node in conf.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if version_match(app_cpe, match):
                        matched = True
                        break
                if matched: break
            if matched: break
            
        if matched:
            out.append({"id": cve_id, "description": desc, "score": score, "severity": sev, "published": pub})
            
    out.sort(key=lambda x: x.get("score", 0), reverse=True)
    cache[app_cpe] = out
    return out

# ── POSTURE ──
SP={"CRITICAL":15,"HIGH":8,"MEDIUM":3,"LOW":1}
def _pscore(cves):
    if not cves: return 100
    return max(0,100-sum(SP.get(c.get("severity",""),1) for c in cves))
def _plabel(s): return "Excellent" if s>=90 else "Good" if s>=75 else "Fair" if s>=50 else "Poor" if s>=25 else "Critical"
def _phex(s): return "27AE60" if s>=90 else "2ECC71" if s>=75 else "F39C12" if s>=50 else "E67E22" if s>=25 else "C0392B"

# ── PATCH COVERAGE ──
PMPC_KW=["1password","7-zip","adobe acrobat","adobe reader","adobe creative cloud","audacity","bitwarden","blender","brave","calibre","citrix workspace","cyberduck","discord","docker desktop","dropbox","evernote","filezilla","firefox","foxit","gimp","git","github desktop","google chrome","google drive","greenshot","handbrake","inkscape","irfanview","java","jre","keepass","keepassxc","lastpass","libreoffice","malwarebytes","microsoft edge","microsoft teams","microsoft onedrive","microsoft office","microsoft 365","notepad++","obs studio","opera","paint.net","postman","putty","python","ringcentral","sharex","signal","skype","slack","snagit","spotify","sublime text","teamviewer","telegram","thunderbird","tor browser","veracrypt","visual studio code","vlc","vnc","webex","wireshark","winscp","winzip","zoom","zscaler"]
JAMF_KW=["1password","adobe acrobat","adobe creative cloud","adobe reader","audacity","bitwarden","blender","brave","calibre","citrix workspace","cyberduck","discord","docker","dropbox","evernote","figma","filezilla","firefox","gimp","github desktop","google chrome","google drive","grammarly","handbrake","inkscape","iterm2","java","jre","keepassxc","lastpass","libreoffice","malwarebytes","microsoft edge","microsoft excel","microsoft onenote","microsoft outlook","microsoft powerpoint","microsoft teams","microsoft word","microsoft onedrive","notion","obs","obsidian","opera","postman","python","signal","sketch","skype","slack","snagit","spotify","sublime text","teamviewer","telegram","thunderbird","visual studio code","vlc","webex","wireshark","xcode","zoom","zscaler"]

def _patch_match(name,kws):
    n=name.lower().strip()
    return any(k in n or n.startswith(k) for k in kws)

def _patch_coverage(apps_list,platform):
    kws=PMPC_KW if platform=="windows" else JAMF_KW
    uniq={a["displayName"]:a["version"] for a in apps_list if a.get("displayName")}
    patchable={n for n in uniq if _patch_match(n,kws)}
    return len(uniq),len(patchable),patchable

def _closable_cves(patchable,results,plat_devs):
    dns={d.get("deviceName") for d in plat_devs}; out=set()
    for r in results:
        if r.get("device_name") not in dns or r.get("type")=="os": continue
        for pn in patchable:
            if pn.lower() in r.get("source_label","").lower():
                for c in r.get("cves",[]): out.add(c["id"])
                break
    return out

# ── REPORT ──
NAVY=RGBColor(0x1B,0x2A,0x4A); ACCENT=RGBColor(0x2E,0x75,0xB6); WHITE=RGBColor(0xFF,0xFF,0xFF)
GREY=RGBColor(0x95,0xA5,0xA6); DARK=RGBColor(0x2C,0x3E,0x50); LBG="F2F4F7"

def _shd(c,h):
    tc=c._element.get_or_add_tcPr(); tc.append(tc.makeelement(qn('w:shd'),{qn('w:fill'):h,qn('w:val'):'clear'}))
def _sc(c,sz=10,b=False,cl=None):
    for p in c.paragraphs:
        for r in p.runs:
            r.font.name="Arial"; r.font.size=Pt(sz)
            if b: r.bold=True
            if cl: r.font.color.rgb=cl
def _hr(t,hs):
    for i,h in enumerate(hs): t.cell(0,i).text=h; _shd(t.cell(0,i),"1B2A4A"); _sc(t.cell(0,i),9,True,WHITE)
def _ap(d,text,sz=11,b=False,c=None,al=None,sa=6):
    p=d.add_paragraph(); r=p.add_run(text); r.font.size=Pt(sz); r.font.name="Arial"
    if b: r.bold=True
    if c: r.font.color.rgb=c
    if al: p.alignment=al
    p.paragraph_format.space_after=Pt(sa); return p
def _rule(d):
    p=d.add_paragraph(); p.alignment=WD_ALIGN_PARAGRAPH.CENTER
    r=p.add_run("━"*50); r.font.color.rgb=ACCENT; r.font.size=Pt(8); p.paragraph_format.space_after=Pt(12)
def _sevt(cves):
    s=defaultdict(int)
    for c in cves: s[c["severity"]]+=1
    return f"Critical: {s['CRITICAL']}, High: {s['HIGH']}, Medium: {s['MEDIUM']}, Low: {s['LOW']}"

# ── Formula injection neutralisation (PAT-865) ──
# Local copy of intune_upload.neutralise_formula/_nf: duplicated rather than
# imported because intune_upload.py already imports report helpers FROM this
# module, so importing back would be circular. Keep behaviour identical: call
# at every docx-cell output boundary for a value that originates from the
# uploaded CSV (or, for the CVE inventory table, the NVD description).
_FORMULA_PREFIXES = ('=', '+', '-', '@')
def neutralise_formula(value):
    """Prefix formula-injection strings with ' to neutralise spreadsheet execution."""
    if value and value[0] in _FORMULA_PREFIXES: return "'"+value
    return value
def _nf(value):
    """neutralise_formula with safe str cast."""
    return neutralise_formula(str(value)) if value is not None else ""

def _apply_table_borders(tbl, color="1B2A4A", weight="12"):
    """Apply consistent borders to a table (lighter line weight)"""
    tblPr=tbl._element.tblPr
    tblBorders=tblPr.first_child_found_in("w:tblBorders")
    if tblBorders is None:
        tblBorders=OxmlElement("w:tblBorders")
        tblPr.append(tblBorders)
    for b in ["top","left","bottom","right","insideH","insideV"]:
        br=OxmlElement(f"w:{b}"); br.set(qn("w:val"),"single"); br.set(qn("w:sz"),weight); br.set(qn("w:space"),"0"); br.set(qn("w:color"),color)
        tblBorders.append(br)

def _gen_report(full,devices,company,dd,win_d,mac_d,da,logo_path,out,has_app_data=True):
    doc=Document(); now=datetime.now(timezone.utc)
    for s in doc.sections: s.top_margin=s.bottom_margin=s.left_margin=s.right_margin=Cm(2.54)
    doc.styles["Normal"].font.name="Arial"; doc.styles["Normal"].font.size=Pt(11)

    # TITLE PAGE
    for _ in range(2): doc.add_paragraph()

    # Logo
    if logo_path and os.path.exists(logo_path):
        lp=doc.add_paragraph(); lp.alignment=WD_ALIGN_PARAGRAPH.CENTER
        lp.add_run().add_picture(logo_path,width=Inches(3.5))
        lp.paragraph_format.space_after=Pt(20)

    _ap(doc,"Endpoint Security  |  Compliance  |  Patch Management",11,c=GREY,al=WD_ALIGN_PARAGRAPH.CENTER,sa=30)
    _rule(doc)
    _ap(doc,"CVE Vulnerability Assessment",28,True,ACCENT,WD_ALIGN_PARAGRAPH.CENTER,30)
    _ap(doc,"Prepared for",14,c=GREY,al=WD_ALIGN_PARAGRAPH.CENTER,sa=4)
    _ap(doc,company,22,True,NAVY,WD_ALIGN_PARAGRAPH.CENTER,30)
    _ap(doc,f"Report Date: {now.strftime('%d %B %Y')}",12,c=DARK,al=WD_ALIGN_PARAGRAPH.CENTER,sa=4)
    _ap(doc,"Classification: Confidential",11,c=GREY,al=WD_ALIGN_PARAGRAPH.CENTER,sa=4)
    _ap(doc,"Prepared by Patched.im Ltd  |  patched.im",11,c=GREY,al=WD_ALIGN_PARAGRAPH.CENTER)
    doc.add_page_break()

    # COMPUTE
    all_u,all_os,all_app=set(),set(),set(); sev=defaultdict(int)
    for d in dd.values():
        for c in d["os_cves"]:
            if c["id"] not in all_u: all_u.add(c["id"]); sev[c["severity"]]+=1
            all_os.add(c["id"])
        for c in d["app_cves"]:
            if c["id"] not in all_u: all_u.add(c["id"]); sev[c["severity"]]+=1
            all_app.add(c["id"])

    # ESTATE SUMMARY
    _ap(doc,"Estate Summary",22,True,NAVY,sa=12)
    _ap(doc,f"Patched.im scanned {len(devices)} Intune-managed device(s) belonging to {company}, "
        f"including {len(win_d)} Windows and {len(mac_d)} macOS device(s). Each device was assessed "
        f"for OS and third-party application vulnerabilities against the NIST NVD.",sa=12)
    t=doc.add_table(2,4); t.alignment=WD_TABLE_ALIGNMENT.CENTER; _apply_table_borders(t)
    for i,h in enumerate(["Devices Scanned","Total Unique CVEs","OS CVEs","App CVEs"]):
        t.cell(0,i).text=h; _shd(t.cell(0,i),"1B2A4A"); _sc(t.cell(0,i),9,True,WHITE)
    for i,v in enumerate([str(len(devices)),str(len(all_u)),str(len(all_os)),str(len(all_app))]):
        c=t.cell(1,i); c.text=v; _shd(c,LBG); _sc(c,14,True,NAVY)
        for p in c.paragraphs: p.alignment=WD_ALIGN_PARAGRAPH.CENTER
    doc.add_paragraph()
    _ap(doc,"CVE Severity Breakdown",14,True,ACCENT,sa=8)
    st=doc.add_table(2,4); st.alignment=WD_TABLE_ALIGNMENT.LEFT; _apply_table_borders(st)
    for i,(l,k,cl) in enumerate([("Critical","CRITICAL","C0392B"),("High","HIGH","E67E22"),("Medium","MEDIUM","F39C12"),("Low","LOW","27AE60")]):
        st.cell(0,i).text=l; _shd(st.cell(0,i),cl); _sc(st.cell(0,i),9,True,WHITE)
        st.cell(1,i).text=str(sev.get(k,0)); _sc(st.cell(1,i),12,True,NAVY)
        for p in st.cell(1,i).paragraphs: p.alignment=WD_ALIGN_PARAGRAPH.CENTER
    doc.add_paragraph(); doc.add_page_break()

    # POSTURE TABLE
    _ap(doc,"Device Security Posture",22,True,NAVY,sa=8)
    _ap(doc,"Each device is scored 0–100. Deductions weighted by CVE severity.",sa=12)
    ph=["Device","Platform","Posture","Rating","OS CVEs","App CVEs","Total"]
    pt=doc.add_table(1+len(devices),7); pt.alignment=WD_TABLE_ALIGNMENT.LEFT; _apply_table_borders(pt); _hr(pt,ph)
    for ri,dev in enumerate(devices,1):
        dn=dev.get("deviceName","?"); d=dd.get(dn,{}); ac=d.get("os_cves",[])+d.get("app_cves",[])
        s=_pscore(ac); ok=dev.get("operatingSystem","").lower()
        plat=_fwin(d.get("os_version","")) if ok=="windows" else f"macOS {_cmac(d.get('os_version',''))}" if ok=="macos" else d.get("os","?")
        for ci,v in enumerate([_nf(dn),_nf(plat),f"{s}/100",_plabel(s),str(len(d.get("os_cves",[]))),str(len(d.get("app_cves",[]))),str(len(ac))]):
            pt.cell(ri,ci).text=v; _sc(pt.cell(ri,ci),9)
        for ci in [2,3]: _shd(pt.cell(ri,ci),_phex(s)); _sc(pt.cell(ri,ci),9,True,WHITE)
    doc.add_paragraph(); doc.add_page_break()

    # WINDOWS SUMMARY
    if win_d:
        _ap(doc,"Windows Devices",22,True,NAVY,sa=8)
        wo=sum(len(dd.get(d.get("deviceName",""),{}).get("os_cves",[])) for d in win_d)
        wa=sum(len(dd.get(d.get("deviceName",""),{}).get("app_cves",[])) for d in win_d)
        _ap(doc,f"{len(win_d)} Windows device(s) — {wo} OS CVE(s), {wa} app CVE(s).",sa=12)
        wt=doc.add_table(1+len(win_d),5); wt.alignment=WD_TABLE_ALIGNMENT.LEFT; _apply_table_borders(wt)
        _hr(wt,["Device","Version","Posture","OS CVEs","App CVEs"])
        for ri,dev in enumerate(win_d,1):
            dn=dev.get("deviceName","?"); d=dd.get(dn,{}); ac=d.get("os_cves",[])+d.get("app_cves",[]); s=_pscore(ac)
            for ci,v in enumerate([_nf(dn),_fwin(d.get("os_version","")),f"{s}/100",str(len(d.get("os_cves",[]))),str(len(d.get("app_cves",[])))]):
                wt.cell(ri,ci).text=v; _sc(wt.cell(ri,ci),9)
            _shd(wt.cell(ri,2),_phex(s)); _sc(wt.cell(ri,2),9,True,WHITE)
        doc.add_paragraph(); doc.add_page_break()

    # macOS SUMMARY
    if mac_d:
        _ap(doc,"macOS Devices",22,True,NAVY,sa=8)
        mo=sum(len(dd.get(d.get("deviceName",""),{}).get("os_cves",[])) for d in mac_d)
        ma=sum(len(dd.get(d.get("deviceName",""),{}).get("app_cves",[])) for d in mac_d)
        _ap(doc,f"{len(mac_d)} macOS device(s) — {mo} OS CVE(s), {ma} app CVE(s).",sa=12)
        mt=doc.add_table(1+len(mac_d),5); mt.alignment=WD_TABLE_ALIGNMENT.LEFT; _apply_table_borders(mt)
        _hr(mt,["Device","Version","Posture","OS CVEs","App CVEs"])
        for ri,dev in enumerate(mac_d,1):
            dn=dev.get("deviceName","?"); d=dd.get(dn,{}); ac=d.get("os_cves",[])+d.get("app_cves",[]); s=_pscore(ac)
            for ci,v in enumerate([_nf(dn),f"macOS {_cmac(d.get('os_version',''))}",f"{s}/100",str(len(d.get("os_cves",[]))),str(len(d.get("app_cves",[])))]):
                mt.cell(ri,ci).text=v; _sc(mt.cell(ri,ci),9)
            _shd(mt.cell(ri,2),_phex(s)); _sc(mt.cell(ri,2),9,True,WHITE)
        doc.add_paragraph(); doc.add_page_break()

    # PATCH COVERAGE
    _ap(doc,"What Patched.im Can Do For You",22,True,NAVY,sa=12)
    _ap(doc,"Endpoint patching options: third-party apps (Patch My PC, Jamf App Installers) and OS updates (Windows Update, macOS System Update).",sa=12)
    if not has_app_data:
        _ap(doc,"Application-level scanning not available",16,True,ACCENT,sa=8)
        _ap(doc,"This assessment was generated from a device-only export. Application inventory "
            "data was not provided, so application-level CVE detection and third-party patch "
            "coverage (Patch My PC / Jamf App Installers) are not shown.",sa=8)
        _ap(doc,"To unlock application-level scanning, enable the Intune detected-apps "
            "inventory policy and re-run with the discovered-apps export. Patched.im can "
            "configure this policy as part of onboarding.",sa=12)
    if win_d and has_app_data:
        wapps=[a for dev in win_d for a in da.get(dev["id"],[])]
        wt2,wp,wpn=_patch_coverage(wapps,"windows"); wc=_closable_cves(wpn,full,win_d)
        _ap(doc,"Windows — Patch My PC",16,True,ACCENT,sa=8)
        wpt=doc.add_table(2,3); wpt.alignment=WD_TABLE_ALIGNMENT.LEFT; _apply_table_borders(wpt)
        _hr(wpt,["Total Apps","Patchable by Patched.im","App CVEs Closable"])
        for ci,v in enumerate([str(wt2),f"{wp} / {wt2}",str(len(wc))]):
            wpt.cell(1,ci).text=v; _sc(wpt.cell(1,ci),12,True,NAVY)
            for p in wpt.cell(1,ci).paragraphs: p.alignment=WD_ALIGN_PARAGRAPH.CENTER
        if wp>0: _shd(wpt.cell(1,1),"27AE60"); _sc(wpt.cell(1,1),12,True,WHITE)
        if len(wc)>0: _shd(wpt.cell(1,2),"27AE60"); _sc(wpt.cell(1,2),12,True,WHITE)
        pct=round(wp/wt2*100) if wt2 else 0
        _ap(doc,f"Patched.im can patch {wp}/{wt2} Windows apps ({pct}%), closing {len(wc)} CVE(s) via Patch My PC.",sa=12)
        doc.add_paragraph()
    if mac_d and has_app_data:
        mapps=[a for dev in mac_d for a in da.get(dev["id"],[])]
        mt2,mp,mpn=_patch_coverage(mapps,"macos"); mc=_closable_cves(mpn,full,mac_d)
        _ap(doc,"macOS — Jamf App Installers",16,True,ACCENT,sa=8)
        mpt=doc.add_table(2,3); mpt.alignment=WD_TABLE_ALIGNMENT.LEFT; _apply_table_borders(mpt)
        _hr(mpt,["Total Apps","Patchable by Patched.im","App CVEs Closable"])
        for ci,v in enumerate([str(mt2),f"{mp} / {mt2}",str(len(mc))]):
            mpt.cell(1,ci).text=v; _sc(mpt.cell(1,ci),12,True,NAVY)
            for p in mpt.cell(1,ci).paragraphs: p.alignment=WD_ALIGN_PARAGRAPH.CENTER
        if mp>0: _shd(mpt.cell(1,1),"27AE60"); _sc(mpt.cell(1,1),12,True,WHITE)
        if len(mc)>0: _shd(mpt.cell(1,2),"27AE60"); _sc(mpt.cell(1,2),12,True,WHITE)
        pct=round(mp/mt2*100) if mt2 else 0
        _ap(doc,f"Patched.im can patch {mp}/{mt2} macOS apps ({pct}%), closing {len(mc)} CVE(s) via Jamf App Installers.",sa=12)
    
    # Windows Auto Update
    if win_d:
        doc.add_paragraph()
        win_os_cves=sum(len(dd.get(d.get("deviceName",""),{}).get("os_cves",[])) for d in win_d)
        _ap(doc,"Windows — Auto Update",16,True,ACCENT,sa=8)
        waut=doc.add_table(2,2); waut.alignment=WD_TABLE_ALIGNMENT.LEFT; _apply_table_borders(waut)
        _hr(waut,["Windows Devices","OS CVEs Closable via Windows Update"])
        for ci,v in enumerate([str(len(win_d)),str(win_os_cves)]):
            waut.cell(1,ci).text=v; _sc(waut.cell(1,ci),12,True,NAVY)
            for p in waut.cell(1,ci).paragraphs: p.alignment=WD_ALIGN_PARAGRAPH.CENTER
        if win_os_cves>0: _shd(waut.cell(1,1),"27AE60"); _sc(waut.cell(1,1),12,True,WHITE)
        _ap(doc,f"Enable automatic Windows Update on {len(win_d)} device(s) to remediate {win_os_cves} OS CVE(s) via Windows Update.",sa=12)
    
    # macOS OS Update
    if mac_d:
        doc.add_paragraph()
        mac_os_cves=sum(len(dd.get(d.get("deviceName",""),{}).get("os_cves",[])) for d in mac_d)
        _ap(doc,"macOS — OS Update",16,True,ACCENT,sa=8)
        maut=doc.add_table(2,2); maut.alignment=WD_TABLE_ALIGNMENT.LEFT; _apply_table_borders(maut)
        _hr(maut,["macOS Devices","OS CVEs Closable via macOS Update"])
        for ci,v in enumerate([str(len(mac_d)),str(mac_os_cves)]):
            maut.cell(1,ci).text=v; _sc(maut.cell(1,ci),12,True,NAVY)
            for p in maut.cell(1,ci).paragraphs: p.alignment=WD_ALIGN_PARAGRAPH.CENTER
        if mac_os_cves>0: _shd(maut.cell(1,1),"27AE60"); _sc(maut.cell(1,1),12,True,WHITE)
        _ap(doc,f"Enable automatic macOS Update on {len(mac_d)} device(s) to remediate {mac_os_cves} OS CVE(s) via macOS System Update.",sa=12)
    
    doc.add_page_break()

    # CVE SUMMARY TABLE
    _ap(doc,"CVE Inventory",22,True,NAVY,sa=12)
    _ap(doc,"Complete list of unique CVEs discovered across all devices.",sa=12)
    
    # Collect all CVEs and count occurrences, track OS
    cve_count={}
    for dn,d in dd.items():
        os_type=d.get("os","Unknown").lower()
        for c in d["os_cves"]+d["app_cves"]:
            cid=c.get("id","Unknown")
            if cid not in cve_count:
                cve_count[cid]={"id":cid,"name":c.get("description","")[:80],"severity":c.get("severity","Unknown"),"count":0,"os_set":set()}
            cve_count[cid]["count"]+=1
            cve_count[cid]["os_set"].add(os_type)
    
    # Sort by count descending, then severity
    severity_order={"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
    sorted_cves=sorted(cve_count.values(),key=lambda x:(-x["count"],severity_order.get(x["severity"],99)))
    
    # Create table with box border
    if sorted_cves:
        tbl=doc.add_table(1+len(sorted_cves),5); tbl.alignment=WD_TABLE_ALIGNMENT.LEFT; _apply_table_borders(tbl)
        _hr(tbl,["CVE ID","Severity","Occurrences","OS","Description"])
        for ri,cve in enumerate(sorted_cves,1):
            sev=cve["severity"]
            color={"CRITICAL":"C0392B","HIGH":"E67E22","MEDIUM":"F39C12","LOW":"27AE60"}.get(sev,"999999")
            os_map={"windows":"Windows","macos":"macOS"}
            os_list=", ".join(sorted([os_map.get(o,o.title()) for o in cve["os_set"]]))
            tbl.cell(ri,0).text=cve["id"]; _sc(tbl.cell(ri,0),8)
            tbl.cell(ri,1).text=sev; _shd(tbl.cell(ri,1),color); _sc(tbl.cell(ri,1),8,True,WHITE)
            tbl.cell(ri,2).text=str(cve["count"]); _sc(tbl.cell(ri,2),8)
            tbl.cell(ri,3).text=_nf(os_list) if os_list else "Unknown"; _sc(tbl.cell(ri,3),8)
            tbl.cell(ri,4).text=_nf(cve["name"]); _sc(tbl.cell(ri,4),8)
            for p in tbl.cell(ri,1).paragraphs: p.alignment=WD_ALIGN_PARAGRAPH.CENTER
            for p in tbl.cell(ri,2).paragraphs: p.alignment=WD_ALIGN_PARAGRAPH.CENTER
            for p in tbl.cell(ri,3).paragraphs: p.alignment=WD_ALIGN_PARAGRAPH.CENTER
    else:
        _ap(doc,"No CVEs detected.",sa=12)
    doc.add_paragraph(); doc.add_page_break()

    # RECOMMENDATIONS
    _ap(doc,"Recommendations",22,True,NAVY,sa=12)
    for i,(t,b) in enumerate([
        ("Patch Critical & High CVEs Immediately","Remediate Critical (9.0+) and High (7.0-8.9) vulnerabilities within your next patch cycle."),
        ("Enable Automatic Updates","Enforce automatic OS and application updates through Intune compliance policies."),
        ("Deploy Third-Party Patch Management","Patched.im deploys Patch My PC (Windows) and Jamf App Installers (macOS) to automate third-party patching."),
        ("Establish a Regular Scan Cadence","Monthly vulnerability assessments to track remediation and newly disclosed CVEs."),
        ("Review Compliance Policies","Enforce minimum OS versions and block non-compliant devices via Conditional Access."),
    ],1):
        _ap(doc,f"{i}. {t}",12,True,ACCENT,sa=4); _ap(doc,b,11,sa=12)

    # DISCLAIMER
    doc.add_paragraph(); _rule(doc)
    _ap(doc,"This report was generated by Patched.im Ltd using data from Microsoft Intune and the NIST NVD. "
        "It does not constitute a penetration test. Patch coverage is based on catalogue keyword matching.",9,c=GREY,sa=4)
    _ap(doc,f"Generated: {now.strftime('%d %B %Y %H:%M UTC')}  |  patched.im",9,c=GREY)
    doc.save(out)


# ── UPLOAD PIPELINE ──
# Header aliases for the Intune "All devices" CSV export. Microsoft has shipped
# multiple variants over the years; accept the common spellings rather than
# pinning one.
_DEV_ALIASES = {
    "deviceName":    ["device name","devicename","name","host name","hostname"],
    "operatingSystem":["os","operating system","platform"],
    "osVersion":     ["os version","operating system version","osversion"],
    "complianceState":["compliance","compliance state","compliancestate"],
    "lastSyncDateTime":["last check-in","last sync","last sync date time","lastcheckin"],
    "userPrincipalName":["primary user upn","user principal name","upn","primary user","email"],
    "model":         ["model"],
    "manufacturer":  ["manufacturer","make"],
    "serialNumber":  ["serial number","serialnumber","serial"],
}

def _find_col(headers_lower, aliases):
    for a in aliases:
        if a in headers_lower: return headers_lower[a]
    return None

def _parse_devices_csv(path):
    """Parse Intune All devices export. Returns list of dicts matching the
    Graph managedDevices shape used by the rest of the pipeline."""
    with open(path, encoding="utf-8-sig", newline="") as f:
        sample = f.read(4096); f.seek(0)
        try: dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        except: dialect = csv.excel
        reader = csv.DictReader(f, dialect=dialect)
        headers_lower = {h.lower().strip(): h for h in (reader.fieldnames or [])}
        col = {k: _find_col(headers_lower, v) for k, v in _DEV_ALIASES.items()}
        if not col["deviceName"] or not col["operatingSystem"] or not col["osVersion"]:
            raise ValueError("CSV missing required columns (device name, OS, OS version).")

        out = []
        for i, row in enumerate(reader):
            name = (row.get(col["deviceName"]) or "").strip()
            os_name = (row.get(col["operatingSystem"]) or "").strip()
            os_ver = (row.get(col["osVersion"]) or "").strip()
            if not name or not os_ver or os_ver == "0.0.0.0": continue
            out.append({
                "id": f"csv-{i}",
                "deviceName": name,
                "operatingSystem": os_name,
                "osVersion": os_ver,
                "complianceState": (row.get(col["complianceState"]) or "").strip() if col["complianceState"] else "",
                "lastSyncDateTime": (row.get(col["lastSyncDateTime"]) or "").strip() if col["lastSyncDateTime"] else "",
                "userPrincipalName": (row.get(col["userPrincipalName"]) or "").strip() if col["userPrincipalName"] else "",
                "model": (row.get(col["model"]) or "").strip() if col["model"] else "",
                "manufacturer": (row.get(col["manufacturer"]) or "").strip() if col["manufacturer"] else "",
                "serialNumber": (row.get(col["serialNumber"]) or "").strip() if col["serialNumber"] else "",
            })
        return out

def _parse_apps_json(path, devices):
    """Parse a detected-apps JSON export (Graph PowerShell shape: list of
    {displayName, version, managedDevices:[{id|deviceName}]}). Returns a
    dict keyed by device id, value list of {displayName, version}.

    Matches device IDs first; falls back to deviceName if managedDevices
    only carries names (eg. PowerShell formatted without IDs)."""
    with open(path, encoding="utf-8-sig") as f:
        data = json.load(f)
    if isinstance(data, dict) and "value" in data: data = data["value"]
    if not isinstance(data, list): raise ValueError("Apps JSON must be a list.")

    name_to_id = {d["deviceName"]: d["id"] for d in devices}
    ids = {d["id"] for d in devices}
    da = defaultdict(list)
    for app in data:
        n = (app.get("displayName") or "").strip()
        v = (app.get("version") or "").strip()
        if not n: continue
        for md in app.get("managedDevices") or []:
            mid = md.get("id"); mname = md.get("deviceName")
            target = mid if mid in ids else name_to_id.get(mname)
            if target: da[target].append({"displayName": n, "version": v})
    return da


def run_scan_from_upload(devices_csv_path, apps_file_path, nvd_api_key, company_name,
                         logo_path, output_path, on_progress=None):
    """Upload-based scan. Required: Intune All-devices CSV. Optional: detected-apps
    JSON (Graph PowerShell export) for per-device application CVEs."""
    def prog(pct, msg):
        if on_progress: on_progress(pct, msg)

    prog(5, "Parsing devices export...")
    devices = _parse_devices_csv(devices_csv_path)
    if not devices:
        raise ValueError("No valid devices in CSV (need device name + OS + OS version).")
    prog(15, f"Found {len(devices)} valid device(s)")

    da = defaultdict(list)
    has_app_data = False
    if apps_file_path:
        prog(20, "Parsing application inventory...")
        try:
            da = _parse_apps_json(apps_file_path, devices)
            has_app_data = bool(da)
            mapped = sum(len(v) for v in da.values())
            prog(25, f"Mapped {mapped} app instance(s) across {len(da)} device(s)")
        except Exception as e:
            prog(25, f"⚠️ Apps file ignored: {e}")
    else:
        prog(25, "No application inventory provided — OS-only scan")

    targets = []
    for dev in devices:
        dn, did = dev["deviceName"], dev["id"]
        oc = _os_cpe(dev.get("operatingSystem",""), dev.get("osVersion",""))
        if oc: targets.append({"device_name":dn,"source_label":f"{dev.get('operatingSystem','')} {dev.get('osVersion','')}","cpe":oc,"type":"os"})
        for app in da.get(did, []):
            ac = _app_cpe(app["displayName"], app["version"])
            if ac: targets.append({"device_name":dn,"source_label":f"{app['displayName']} {app['version']}","cpe":ac,"type":"app"})

    uniq_cpes = {}
    for t in targets:
        if t["cpe"] not in uniq_cpes: uniq_cpes[t["cpe"]] = t

    prog(30, f"Scanning {len(uniq_cpes)} unique CPE(s) against NVD...")
    cache = {}
    total = len(uniq_cpes) or 1
    for i, (cpe, tgt) in enumerate(uniq_cpes.items(), 1):
        pct = 30 + int((i/total)*55)
        cves = _scan(cpe, nvd_api_key, cache)
        prog(pct, f"[{i}/{total}] {tgt['source_label']} → {len(cves)} CVE(s)")

    full = [{**t, "cves": cache.get(t["cpe"], [])} for t in targets]

    dd = {}
    for dev in devices:
        dn = dev["deviceName"]
        dd[dn] = {"os":dev.get("operatingSystem",""),"os_version":dev.get("osVersion",""),
                  "os_cves":[],"app_cves":[],"os_cve_ids":set(),"app_cve_ids":set()}
    for r in full:
        dn = r.get("device_name","?")
        if dn not in dd: continue
        d = dd[dn]
        for c in r.get("cves", []):
            if r["type"]=="os" and c["id"] not in d["os_cve_ids"]:
                d["os_cves"].append(c); d["os_cve_ids"].add(c["id"])
            elif r["type"]!="os" and c["id"] not in d["app_cve_ids"]:
                d["app_cves"].append(c); d["app_cve_ids"].add(c["id"])

    win_d = [d for d in devices if d.get("operatingSystem","").lower()=="windows"]
    mac_d = [d for d in devices if d.get("operatingSystem","").lower()=="macos"]

    prog(90, "Generating report...")
    _gen_report(full, devices, company_name, dd, win_d, mac_d, da, logo_path, output_path, has_app_data=has_app_data)
    prog(100, "✅ Report complete")
