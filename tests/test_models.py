"""Testes de models.py. Rodar: python -m unittest -v test_models"""

import json
import unittest
import uuid
from datetime import datetime, timedelta, timezone

from src.models import PasswordEntry, Vault


class TestPasswordEntry(unittest.TestCase):
    def test_criacao_auto(self) -> None:
        e = PasswordEntry("GitHub", "user", "s3nh4")
        self.assertIsInstance(e.id, uuid.UUID)
        self.assertIsInstance(e.created_at, datetime)
        self.assertIsInstance(e.updated_at, datetime)

    def test_ids_unicos(self) -> None:
        a = PasswordEntry("a", "u", "p")
        b = PasswordEntry("a", "u", "p")
        self.assertNotEqual(a.id, b.id)

    def test_to_dict_iso(self) -> None:
        d = PasswordEntry("s", "u", "p").to_dict()
        self.assertEqual(len(d), 7)
        self.assertIsInstance(d["id"], str)
        datetime.fromisoformat(d["created_at"])

    def test_roundtrip(self) -> None:
        original = PasswordEntry("github", "user", "p", "nota")
        copia = PasswordEntry.from_dict(original.to_dict())
        self.assertEqual(original.to_dict(), copia.to_dict())

    def test_from_dict_erro(self) -> None:
        with self.assertRaises(ValueError):
            PasswordEntry.from_dict({"site": "x"})
        with self.assertRaises(ValueError):
            PasswordEntry.from_dict({"id": "nao-uuid", "site": "x", "username": "u",
                                     "password": "p", "created_at": "2024-01-01T00:00:00",
                                     "updated_at": "2024-01-01T00:00:00"})

    def test_str_mascara(self) -> None:
        self.assertIn("***", str(PasswordEntry("s", "u", "segredo")))
        self.assertNotIn("segredo", str(PasswordEntry("s", "u", "segredo")))

    def test_strip(self) -> None:
        e = PasswordEntry("  github  ", "  user ", " p com espaco ")
        self.assertEqual(e.site, "github")
        self.assertEqual(e.username, "user")
        self.assertEqual(e.password, " p com espaco ")


class TestVault(unittest.TestCase):
    def setUp(self) -> None:
        self.vault = Vault()

    def test_add_get(self) -> None:
        entry = PasswordEntry("github", "user", "p")
        eid = self.vault.add(entry)
        self.assertEqual(eid, str(entry.id))
        self.assertEqual(len(self.vault), 1)
        self.assertIs(self.vault.get(eid), entry)
        self.assertIs(self.vault.get(entry.id), entry)

    def test_get_inexistente(self) -> None:
        self.assertIsNone(self.vault.get(uuid.uuid4()))
        self.assertIsNone(self.vault.get("lixo"))

    def test_list_all_ordem(self) -> None:
        antigo = PasswordEntry("a", "u", "p")
        novo = PasswordEntry("b", "u", "p")
        self.vault.add(antigo)
        self.vault.add(novo)
        antigo.created_at = datetime.now(timezone.utc) - timedelta(days=1)
        self.assertEqual(self.vault.list_all()[0], novo)

    def test_search(self) -> None:
        self.vault.add(PasswordEntry("github", "user", "p"))
        self.vault.add(PasswordEntry("gitlab", "outro", "p"))
        self.assertEqual(len(self.vault.search("github")), 1)
        self.assertEqual(len(self.vault.search("GIT")), 2)
        self.assertEqual(len(self.vault.search("outro")), 1)
        self.assertEqual(len(self.vault.search("")), 2)

    def test_update(self) -> None:
        entry = PasswordEntry("github", "user", "p")
        eid = self.vault.add(entry)
        entry.updated_at = datetime.now(timezone.utc) - timedelta(days=1)
        antes = entry.updated_at
        self.assertTrue(self.vault.update(eid, password="nova", ignorado="x"))
        self.assertEqual(entry.password, "nova")
        self.assertGreater(entry.updated_at, antes)
        self.assertEqual(entry.notes, "")
        self.assertFalse(self.vault.update(uuid.uuid4(), site="x"))

    def test_update_reindexa(self) -> None:
        eid = self.vault.add(PasswordEntry("github", "user", "p"))
        self.vault.update(eid, site="gitlab", username="outro")
        self.assertEqual(self.vault.search("github"), [])
        self.assertEqual(len(self.vault.search("gitlab")), 1)
        self.assertEqual(len(self.vault.search("outro")), 1)

    def test_delete(self) -> None:
        entry = PasswordEntry("github", "user", "p")
        eid = self.vault.add(entry)
        self.assertTrue(self.vault.delete(eid))
        self.assertEqual(len(self.vault), 0)
        self.assertIsNone(self.vault.get(eid))
        self.assertEqual(self.vault.search("github"), [])
        self.assertFalse(self.vault.delete(eid))

    def test_container_protocol(self) -> None:
        entry = PasswordEntry("github", "user", "p")
        self.vault.add(entry)
        self.assertEqual(len(self.vault), 1)
        self.assertEqual(list(self.vault), [entry])
        self.assertIn(entry.id, self.vault)
        self.assertIn(str(entry.id), self.vault)
        self.assertNotIn(uuid.uuid4(), self.vault)
        self.assertNotIn(42, self.vault)

    def test_backup_restore(self) -> None:
        self.vault.add(PasswordEntry("github", "user", "p", "nota"))
        self.vault.add(PasswordEntry("gitlab", "outro", "q"))
        bruto = self.vault.backup()
        self.assertIsInstance(json.loads(bruto.decode("utf-8")), list)
        copia = Vault.restore(bruto)
        self.assertEqual(len(copia), 2)
        self.assertEqual(
            [e.to_dict() for e in copia], [e.to_dict() for e in self.vault]
        )
        self.assertEqual(len(copia.search("gitlab")), 1)

    def test_restore_invalido(self) -> None:
        with self.assertRaises(ValueError):
            Vault.restore(b"nao e json")
        with self.assertRaises(ValueError):
            Vault.restore(b'{"nao": "lista"}')


if __name__ == "__main__":
    unittest.main()
