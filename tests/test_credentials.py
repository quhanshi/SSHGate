from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ssh_gate.credentials import CredentialStore, FileKeyProvider


class CredentialStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = CredentialStore(self.root)
        self.ref = self.store.reference("server-a", "root", "example.test", 22)

    def test_roundtrip_does_not_store_plaintext(self):
        secret = "fixture-private-password"
        self.store.save(self.ref, "password", secret)
        self.assertEqual({"mode": "password", "secret": secret}, self.store.get(self.ref))
        self.assertNotIn(secret, (self.root / "credentials.json").read_text(encoding="utf-8"))
        self.assertEqual(32, len((self.root / "master.key").read_bytes()))


    def test_named_api_key_roundtrip_uses_same_encrypted_store(self):
        ref = self.store.secret_reference("openai-secure-mcp-tunnel-api-key")
        secret = "sk-fixture-private-runtime-key"
        self.store.save(ref, "api_key", secret)
        self.assertEqual({"mode": "api_key", "secret": secret}, self.store.get(ref))
        self.assertNotIn(secret, (self.root / "credentials.json").read_text(encoding="utf-8"))

    def test_wrong_key_discards_only_unreadable_entry(self):
        self.store.save(self.ref, "password", "fixture-private-password")
        other_key = self.root / "other.key"
        other_key.write_bytes(b"x" * 32)
        moved = CredentialStore(self.root, key_provider=FileKeyProvider(other_key))
        self.assertIsNone(moved.get(self.ref))
        self.assertFalse(moved.has(self.ref))

    def test_delete_forgets_credential(self):
        self.store.save(self.ref, "passphrase", "fixture-key-passphrase")
        self.assertTrue(self.store.has(self.ref))
        self.store.delete(self.ref)
        self.assertFalse(self.store.has(self.ref))


if __name__ == "__main__":
    unittest.main()
