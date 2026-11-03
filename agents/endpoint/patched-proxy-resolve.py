#!/usr/bin/env python3
"""
patched-proxy-resolve.py — proxy resolver for the Patched updater.

Usage: patched-proxy-resolve.py <target-url> [<agent-config-json>]

Reads proxy config from the agent-config (optional; defaults to system mode).
Outputs one JSON line; always exits 0 (fail-open → direct on any error).

System mode reads the *static* proxy settings from `scutil --proxy`. PAC
(proxy auto-config) files are NOT evaluated — Apple's stock /usr/bin/python3
(Command Line Tools) ships no PyObjC, so there is no supported way to run a
PAC in-process. When a PAC URL is configured we surface a `warning` and fall
back to any static settings, else direct. PAC users are expected to be rare;
they should pin a static proxy via manual mode instead.

Output shape:
  {"mode": "direct"}
  {"mode": "proxy", "type": "http|socks5", "host": "...", "port": 8080,
   "url": "http://host:port",
   "display_url": "http://host:port",       -- safe to log (creds redacted)
   "no_proxy": "localhost,127.0.0.1",       -- optional
   "warning": "human-readable advisory"}    -- optional; logged, never fatal
"""

import json
import os
import re
import socket
import subprocess
import sys


def _read_proxy_cfg(config_path):
    """Return proxy sub-object from agent-config, or {} if absent/unreadable."""
    if not config_path or not os.path.exists(config_path):
        return {}
    try:
        with open(config_path) as f:
            return json.load(f).get('proxy') or {}
    except Exception:
        return {}


def _keychain_cred(service):
    """Return (username, password) from macOS Keychain, or ('', '') on failure."""
    try:
        raw = subprocess.check_output(
            ['/usr/bin/security', 'find-generic-password', '-s', service],
            text=True, stderr=subprocess.STDOUT, timeout=5)
        m = re.search(r'"acct"[^=\n]*=\s*"([^"]+)"', raw)
        username = m.group(1) if m else ''
        password = subprocess.check_output(
            ['/usr/bin/security', 'find-generic-password', '-s', service, '-w'],
            text=True, stderr=subprocess.DEVNULL, timeout=5).strip()
        return username, password
    except Exception:
        return '', ''


def _build_proxy_result(ptype, host, port, auth_ref=None, no_proxy_list=None):
    """Build a proxy result dict; embed creds in url, redact in display_url."""
    base = f'{ptype}://{host}:{port}'
    warnings = []
    if auth_ref:
        username, password = _keychain_cred(auth_ref)
        if username and password:
            cred_url = f'{ptype}://{username}:{password}@{host}:{port}'
            disp_url = f'{ptype}://[redacted]@{host}:{port}'
            # Basic-auth over a cleartext HTTP proxy exposes the credentials on
            # the wire between client and proxy. Warn (don't refuse) — operators
            # should prefer an HTTPS proxy (type: "https").
            if ptype == 'http':
                warnings.append('proxy credentials are being sent over an '
                                'unencrypted HTTP proxy; prefer an HTTPS proxy '
                                '(set proxy.type to "https")')
        else:
            cred_url = base
            disp_url = base
    else:
        cred_url = base
        disp_url = base

    result = {
        'mode': 'proxy',
        'type': ptype,
        'host': host,
        'port': port,
        'url': cred_url,
        'display_url': disp_url,
    }
    if no_proxy_list:
        entries = no_proxy_list if isinstance(no_proxy_list, list) else [no_proxy_list]
        result['no_proxy'] = ','.join(str(e) for e in entries)
        # curl's NO_PROXY matches exact hosts, domain suffixes and individual
        # IPs — NOT CIDR ranges. A CIDR entry silently never matches, so warn.
        if any('/' in str(e) for e in entries):
            warnings.append('no_proxy contains a CIDR range, which curl does '
                            'not honour; use exact hosts or domain suffixes '
                            '(e.g. "corp.example.com") instead')
    if warnings:
        result['warning'] = '; '.join(warnings)
    return result


def _tcp_reachable(host, port, timeout=2):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def _proxy_reachable(host, port, probe_url=''):
    """Reachability probe. When probe_url is set, GET it (it should be reachable
    only on-corp); otherwise TCP-connect to the proxy host:port."""
    if probe_url:
        try:
            from urllib.request import urlopen
            urlopen(probe_url, timeout=2)
            return True
        except Exception:
            return False
    return _tcp_reachable(host, port)


def _resolve_manual(cfg):
    host = cfg.get('host', '')
    port = int(cfg.get('port', 8080))
    ptype = cfg.get('type', 'http')
    auth_ref = cfg.get('auth_ref') or None
    no_proxy = cfg.get('no_proxy') or []
    bypass = bool(cfg.get('bypass_when_off_corp', False))
    probe_url = cfg.get('probe_url', '')

    if not host:
        return {'mode': 'direct'}

    # Probe reachability before use (always). If the proxy can't be reached:
    #   bypass_when_off_corp=true  -> fall back to direct (roaming laptops).
    #   bypass_when_off_corp=false -> keep the proxy (fail closed: egress errors
    #       rather than silently leaking direct) but warn, so the operator knows
    #       why calls are failing rather than guessing.
    if not _proxy_reachable(host, port, probe_url):
        if bypass:
            return {'mode': 'direct'}
        result = _build_proxy_result(ptype, host, port, auth_ref=auth_ref,
                                     no_proxy_list=no_proxy)
        unreachable = (f'manual proxy {host}:{port} is not reachable; egress '
                       f'will fail until it is (set '
                       f'proxy.bypass_when_off_corp=true to fall back to direct '
                       f'when off-network)')
        result['warning'] = (result['warning'] + '; ' + unreachable
                             if result.get('warning') else unreachable)
        return result

    return _build_proxy_result(ptype, host, port, auth_ref=auth_ref, no_proxy_list=no_proxy)


def _resolve_system(target_url):
    """Static proxy resolution via `scutil --proxy`.

    No PAC support: Apple's stock /usr/bin/python3 ships no PyObjC, so there is
    no in-process way to evaluate a PAC. If a PAC URL is configured we attach a
    `warning` and use any static proxy settings present, else go direct.
    """
    try:
        out = subprocess.check_output(
            ['/usr/sbin/scutil', '--proxy'], text=True, timeout=5)
    except Exception:
        return {'mode': 'direct'}

    lines = {}
    for line in out.splitlines():
        if ':' in line:
            k, _, v = line.partition(':')
            lines[k.strip()] = v.strip()

    pac_warning = None
    if lines.get('ProxyAutoConfigEnable') == '1':
        pac_warning = ('a PAC (proxy auto-config) URL is set in System Settings, '
                       'but this agent does not evaluate PAC files; using static '
                       'proxy settings if present, otherwise connecting direct. '
                       'Pin a static proxy via manual mode to silence this.')

    is_https = target_url.lower().startswith('https://')
    result = {'mode': 'direct'}

    if is_https and lines.get('HTTPSEnable') == '1':
        host = lines.get('HTTPSProxy', '')
        port_str = lines.get('HTTPSPort', '0')
        port = int(port_str) if port_str.isdigit() else 0
        if host and port:
            result = _build_proxy_result('http', host, port)

    if result['mode'] == 'direct' and lines.get('HTTPEnable') == '1':
        host = lines.get('HTTPProxy', '')
        port_str = lines.get('HTTPPort', '0')
        port = int(port_str) if port_str.isdigit() else 0
        if host and port:
            result = _build_proxy_result('http', host, port)

    if result['mode'] == 'direct' and lines.get('SOCKSEnable') == '1':
        host = lines.get('SOCKSProxy', '')
        port_str = lines.get('SOCKSPort', '0')
        port = int(port_str) if port_str.isdigit() else 0
        if host and port:
            result = _build_proxy_result('socks5', host, port)

    if pac_warning:
        existing = result.get('warning')
        result['warning'] = (existing + '; ' + pac_warning) if existing else pac_warning
    return result


def resolve(target_url, config_path=''):
    cfg = _read_proxy_cfg(config_path)
    mode = cfg.get('mode', 'system')

    if mode == 'off':
        return {'mode': 'direct'}

    if mode == 'manual':
        return _resolve_manual(cfg)

    return _resolve_system(target_url)


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else 'https://api.patched.im'
    config = sys.argv[2] if len(sys.argv) > 2 else ''
    try:
        result = resolve(target, config)
    except Exception:
        result = {'mode': 'direct'}
    print(json.dumps(result))
