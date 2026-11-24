"""
Tugas 3 - Verifikasi Digital Signature (RSA + SHA-256)
Mata Kuliah: Kriptografi (Semester 3)
Topik: Praktikum Digital Signature (RSA)
"""

import argparse
import hashlib
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def verify_signature(
    message_path: str = "pesan.docx",
    signature_path: str = "pesan.sig",
    public_key_path: str = "public_key.pem",
) -> bool:
    """Memverifikasi keaslian file pesan.docx menggunakan pesan.sig dan public key."""
    # 1. Baca file pesan, signature, dan public key
    with open(message_path, "rb") as f:
        message_bytes = f.read()

    with open(signature_path, "rb") as f:
        signature = f.read()

    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    # Hitung nilai hash SHA-256 dari pesan yang diterima
    digest_hex = hashlib.sha256(message_bytes).hexdigest()

    print("=== VERIFIKASI DIGITAL SIGNATURE ===")
    print(f"File Pesan       : {message_path} ({len(message_bytes)} bytes)")
    print(f"File Signature   : {signature_path} ({len(signature)} bytes)")
    print(f"Public Key       : {public_key_path}")
    print(f"Hash SHA-256 (h) : {digest_hex}")

    # 2. Lakukan verifikasi RSA-PSS + SHA-256
    try:
        public_key.verify(
            signature,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        print("Hasil Verifikasi : BERHASIL")
        print("Keterangan       : Tanda tangan digital VALID. Pesan asli dan berasal dari pemilik private key.")
        return True
    except InvalidSignature:
        print("Hasil Verifikasi : GAGAL")
        print("Keterangan       : Tanda tangan digital TIDAK VALID. Pesan telah diubah atau public key tidak cocok.")
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verifikasi digital signature RSA + SHA-256")
    parser.add_argument("--message", default="pesan.docx", help="Path file pesan (.docx)")
    parser.add_argument("--signature", default="pesan.sig", help="Path file signature (.sig)")
    parser.add_argument("--public", default="public_key.pem", help="Path file public key (.pem)")
    args = parser.parse_args()

    verify_signature(args.message, args.signature, args.public)
