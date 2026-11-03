#!/usr/bin/env python3
"""
Parse device detail JSON and print verdict summary.
Usage: python3 _parse_verdicts.py <device-detail.json>
"""
import sys, json
from collections import Counter

with open(sys.argv[1]) as f:
    data = json.load(f)

device = data.get('device', {})
compliance = data.get('compliance', {})
evals = data.get('evaluations', [])
counts = Counter(e['status'] for e in evals)

print()
print('=== Device Identity ===')
print(f"  hostname   : {device.get('hostname','?')}")
print(f"  serial     : {device.get('serial','?')}")
print(f"  hw_uuid    : {device.get('hw_uuid','?')}")
print(f"  os_version : {device.get('os_version','?')}")
print(f"  arch       : {device.get('arch','?')}")
print()
print('=== Verdict Counts ===')
for status in ('pass','fail','not_applicable','error'):
    print(f"  {status:<20}: {counts.get(status,0)}")
print(f"  {'TOTAL':<20}: {sum(counts.values())}")
print(f"  {'compliance%':<20}: {compliance.get('compliance_pct',0):.1f}%")

PRIORITY = ['filevault','sip','firewall','gatekeeper','secure_boot','mfa',
            'password','screen_lock','screensaver','ssh','remote_login']

def priority_key(e):
    k = e.get('rule_key','').lower()
    for i, p in enumerate(PRIORITY):
        if p in k:
            return (0, i, e.get('rule_key',''))
    return (1, 0, e.get('rule_key',''))

interesting = sorted(evals, key=priority_key)[:5]
print()
print('=== 5 Most Interesting Rules ===')
for e in interesting:
    val = e.get('observed_value') or '-'
    print(f"  {e['rule_key']:<48} {e['status']:<18} {val}")
print()
