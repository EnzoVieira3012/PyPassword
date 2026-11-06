"""Geracao de QR code para compartilhar credencial com o celular."""

from __future__ import annotations


def mostrar_qr(dados: str) -> bool:
    """Imprime QR code ASCII no terminal. Retorna False se a lib faltar."""
    try:
        import qrcode  # type: ignore[import-untyped]
    except ImportError:
        print("qrcode nao instalado. Instale com: pip install qrcode")
        return False
    qr = qrcode.QRCode(border=1)
    qr.add_data(dados)
    qr.make(fit=True)
    qr.print_ascii(invert=True)
    return True
