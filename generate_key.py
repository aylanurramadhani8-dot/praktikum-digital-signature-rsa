"""
Tugas 1 - Generate Key Pair RSA (minimal 2048-bit)
Mata Kuliah: Kriptografi (Semester 3)
Topik: Praktikum Digital Signature (RSA)
"""

import argparse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_rsa_key_pair(
    private_key_path: str = "private_key.pem",
    public_key_path: str = "public_key.pem",
    key_size: int = 2048,
) -> None:
    """Menghasilkan pasangan kunci RSA (private key & public key) dan menyimpannya ke file PEM."""
    if key_size < 2048:
        raise ValueError("Ukuran kunci RSA minimal 2048-bit sesuai instruksi praktikum.")

    # 1. Bangkitkan Private Key RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    # 2. Ambil Public Key yang berpasangan
    public_key = private_key.public_key()

    # 3. Simpan Private Key dalam format PEM (PKCS8)
    with open(private_key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # 4. Simpan Public Key dalam format PEM (SubjectPublicKeyInfo)
    with open(public_key_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print("=== GENERATE KEY PAIR RSA ===")
    print(f"Ukuran Kunci : {key_size}-bit")
    print(f"Private Key  : {private_key_path} (berhasil disimpan)")
    print(f"Public Key   : {public_key_path} (berhasil disimpan)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate RSA Key Pair (minimal 2048-bit)")
    parser.add_argument("--private", default="private_key.pem", help="Path output private key")
    parser.add_argument("--public", default="public_key.pem", help="Path output public key")
    parser.add_argument("--bits", type=int, default=2048, help="Ukuran kunci RSA dalam bit (min 2048)")
    args = parser.parse_args()

    generate_rsa_key_pair(args.private, args.public, args.bits)
