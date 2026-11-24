"""
Tugas 2 - Membuat Digital Signature (RSA + SHA-256)
Mata Kuliah: Kriptografi (Semester 3)
Topik: Praktikum Digital Signature (RSA)
"""

import argparse
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def create_signature(
    message_path: str = "pesan.docx",
    private_key_path: str = "private_key.pem",
    signature_path: str = "pesan.sig",
) -> None:
    """Membaca file pesan.docx, membuat signature digital RSA+SHA-256, dan menyimpannya ke pesan.sig."""
    # 1. Baca isi file pesan.docx sebagai bytes
    with open(message_path, "rb") as f:
        message_bytes = f.read()

    # Hitung nilai hash SHA-256 untuk ditampilkan (h = H(M))
    digest_hex = hashlib.sha256(message_bytes).hexdigest()

    # 2. Muat Private Key pengirim
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # 3. Buat tanda tangan digital menggunakan RSA-PSS + SHA-256
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    # 4. Simpan signature ke file pesan.sig
    with open(signature_path, "wb") as f:
        f.write(signature)

    print("=== PEMBUATAN DIGITAL SIGNATURE (SIGNING) ===")
    print(f"File Pesan       : {message_path} ({len(message_bytes)} bytes)")
    print(f"Private Key      : {private_key_path}")
    print(f"Hash SHA-256 (h) : {digest_hex}")
    print(f"Ukuran Signature : {len(signature)} bytes ({len(signature) * 8}-bit)")
    print(f"File Signature   : {signature_path} (berhasil disimpan)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Membuat digital signature untuk file pesan.docx")
    parser.add_argument("--message", default="pesan.docx", help="Path file pesan (.docx)")
    parser.add_argument("--private", default="private_key.pem", help="Path file private key")
    parser.add_argument("--output", default="pesan.sig", help="Path output file signature")
    args = parser.parse_args()

    create_signature(args.message, args.private, args.output)
