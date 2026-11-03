#!/usr/bin/env python3
"""
PAT-481: Unit tests for the macOS removable-storage detection block
embedded in patched-update.sh.

The detection logic runs inside an embedded Python heredoc in the shell
script. These tests replicate the exact logic so we can exercise it without
needing actual external disks or running the full daemon.

Run with: python3 endpoint/test-removable-storage-detection.py
"""

import unittest

# ──────────────────────────────────────────────────────────────────────────────
# Detection logic (mirrors the embedded block in patched-update.sh exactly)
# ──────────────────────────────────────────────────────────────────────────────

def classify_volume(info: dict) -> dict | None:
    """
    Given a diskutil info plist dict, return a volume record if it is an
    unencrypted external volume, otherwise return None.

    Returns:
        dict with mount_point / filesystem / encryption_state / provenance_source
        or None if the volume is internal, unmounted, already encrypted, or
        an unknown filesystem.
    """
    mount = info.get('MountPoint', '') or ''
    if not mount or mount == '/':
        return None
    if info.get('Internal', True):
        return None

    fs = info.get('FilesystemType', '') or ''
    fs_lower = fs.lower()
    filevault = info.get('FileVault', False)

    if fs_lower in ('msdos', 'exfat', 'hfs'):
        enc_state = 'plaintext'
    elif fs_lower == 'apfs' and not filevault:
        enc_state = 'apfs_unencrypted'
    else:
        return None

    return {
        'mount_point':       mount,
        'filesystem':        fs if fs else 'unknown',
        'encryption_state':  enc_state,
        'provenance_source': 'diskutil',
    }


def build_finding(volumes: list) -> dict | None:
    """Wrap a non-empty volume list into a compliance_finding dict."""
    if not volumes:
        return None
    return {
        'id':       'removable_storage_unencrypted',
        'severity': 'medium',
        'volumes':  volumes,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestClassifyVolume(unittest.TestCase):

    def _ext(self, **kwargs) -> dict:
        """Build a minimal external-volume info dict."""
        base = {
            'MountPoint': '/Volumes/USB',
            'Internal':   False,
            'FilesystemType': 'msdos',
            'FileVault':  False,
        }
        base.update(kwargs)
        return base

    # --- volumes that SHOULD be flagged ---

    def test_fat32_external_flagged(self):
        vol = self._ext(FilesystemType='msdos')
        result = classify_volume(vol)
        self.assertIsNotNone(result)
        self.assertEqual(result['encryption_state'], 'plaintext')
        self.assertEqual(result['filesystem'], 'msdos')
        self.assertEqual(result['provenance_source'], 'diskutil')

    def test_exfat_external_flagged(self):
        vol = self._ext(FilesystemType='exfat', MountPoint='/Volumes/EXFAT')
        result = classify_volume(vol)
        self.assertIsNotNone(result)
        self.assertEqual(result['encryption_state'], 'plaintext')

    def test_hfsplus_external_flagged(self):
        vol = self._ext(FilesystemType='hfs', MountPoint='/Volumes/HFS')
        result = classify_volume(vol)
        self.assertIsNotNone(result)
        self.assertEqual(result['encryption_state'], 'plaintext')

    def test_apfs_no_filevault_flagged(self):
        vol = self._ext(FilesystemType='apfs', FileVault=False, MountPoint='/Volumes/APFS')
        result = classify_volume(vol)
        self.assertIsNotNone(result)
        self.assertEqual(result['encryption_state'], 'apfs_unencrypted')

    # --- volumes that MUST NOT be flagged ---

    def test_apfs_filevault_on_not_flagged(self):
        vol = self._ext(FilesystemType='apfs', FileVault=True)
        self.assertIsNone(classify_volume(vol))

    def test_internal_volume_not_flagged(self):
        vol = self._ext(Internal=True)
        self.assertIsNone(classify_volume(vol))

    def test_unmounted_volume_not_flagged(self):
        vol = self._ext(MountPoint='', Internal=False)
        self.assertIsNone(classify_volume(vol))

    def test_root_volume_not_flagged(self):
        vol = self._ext(MountPoint='/')
        self.assertIsNone(classify_volume(vol))

    def test_unknown_filesystem_not_flagged(self):
        # e.g. ISO 9660 / UDF read-only optical media
        vol = self._ext(FilesystemType='udf')
        self.assertIsNone(classify_volume(vol))

    def test_missing_mount_point_not_flagged(self):
        vol = self._ext()
        vol.pop('MountPoint')
        self.assertIsNone(classify_volume(vol))

    # --- field values ---

    def test_mount_point_preserved(self):
        vol = self._ext(MountPoint='/Volumes/MY DRIVE', FilesystemType='exfat')
        result = classify_volume(vol)
        self.assertEqual(result['mount_point'], '/Volumes/MY DRIVE')

    def test_empty_filesystem_becomes_unknown(self):
        vol = self._ext(FilesystemType='msdos')
        vol['FilesystemType'] = ''
        result = classify_volume(vol)
        # empty string fs_lower is not in the flagged set, so None
        self.assertIsNone(result)


class TestBuildFinding(unittest.TestCase):

    def test_empty_volumes_returns_none(self):
        self.assertIsNone(build_finding([]))

    def test_non_empty_volumes_returns_finding(self):
        vols = [{'mount_point': 'E:', 'filesystem': 'FAT32',
                  'encryption_state': 'plaintext', 'provenance_source': 'diskutil'}]
        finding = build_finding(vols)
        self.assertIsNotNone(finding)
        self.assertEqual(finding['id'],       'removable_storage_unencrypted')
        self.assertEqual(finding['severity'], 'medium')
        self.assertEqual(finding['volumes'],  vols)

    def test_multiple_volumes_all_present(self):
        vols = [
            {'mount_point': '/Volumes/A', 'filesystem': 'msdos',
             'encryption_state': 'plaintext', 'provenance_source': 'diskutil'},
            {'mount_point': '/Volumes/B', 'filesystem': 'exfat',
             'encryption_state': 'plaintext', 'provenance_source': 'diskutil'},
        ]
        finding = build_finding(vols)
        self.assertEqual(len(finding['volumes']), 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
