#!/usr/bin/env python3
"""
Write baseline-verdicts.json from device detail JSON.
Usage: python3 _write_verdicts.py <device-detail.json> <output.json>
"""
import sys, json, datetime
from collections import Counter

with open(sys.argv[1]) as f:
    data = json.load(f)

device = data.get('device', {})
compliance = data.get('compliance', {})
evals = data.get('evaluations', [])
counts = Counter(e['status'] for e in evals)

out = {
    'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'device_id': device.get('id',''),
    'device_hostname': device.get('hostname',''),
    'device_serial': device.get('serial',''),
    'device_hw_uuid': device.get('hw_uuid',''),
    'os_version': device.get('os_version',''),
    'verdict_counts': dict(counts),
    'compliance_pct': compliance.get('compliance_pct',0),
    'verdicts': [
        {
            'rule_key': e['rule_key'],
            'title': e.get('title',''),
            'severity': e.get('severity',''),
            'status': e['status'],
            'observed_value': e.get('observed_value'),
        }
        for e in sorted(evals, key=lambda x: x['rule_key'])
    ]
}
with open(sys.argv[2], 'w') as f:
    json.dump(out, f, indent=2)
    f.write('\n')
print(f"Wrote {len(out['verdicts'])} verdicts to {sys.argv[2]}")
