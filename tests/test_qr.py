"""Testes do QR code."""

from __future__ import annotations

import sys
import unittest
from io import StringIO
from unittest import mock

from src.qr import mostrar_qr


class TestQR(unittest.TestCase):
    def test_mostrar_qr_sem_lib(self) -> None:
        buf = StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            with mock.patch.dict(sys.modules, {"qrcode": None}):
                ok = mostrar_qr("segredo")
        finally:
            sys.stdout = old
        self.assertFalse(ok)
        self.assertIn("qrcode nao instalado", buf.getvalue())

    def test_mostrar_qr_com_lib(self) -> None:
        fake_qr = mock.MagicMock()
        fake_module = mock.MagicMock()
        fake_module.QRCode.return_value = fake_qr
        with mock.patch.dict(sys.modules, {"qrcode": fake_module}):
            ok = mostrar_qr("segredo")
        self.assertTrue(ok)
        fake_qr.add_data.assert_called_once_with("segredo")
        fake_qr.make.assert_called_once_with(fit=True)


if __name__ == "__main__":
    unittest.main()
