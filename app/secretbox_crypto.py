#!/usr/bin/env python3
import argparse
import base64
import os
import sys

import nacl.utils
from nacl.exceptions import CryptoError
from nacl.secret import SecretBox

ENV_KEY_NAME = "SECRETBOX_KEY_B64"


def get_box_from_env() -> SecretBox:
    """Charge la clé depuis la variable d'environnement SECRETBOX_KEY_B64 et construit une SecretBox."""
    key_b64 = os.environ.get(ENV_KEY_NAME)
    if not key_b64:
        raise RuntimeError(
            f"Variable d'environnement {ENV_KEY_NAME} manquante. "
            f"Ajoute un Codespaces Secret nommé {ENV_KEY_NAME} (clé base64 de 32 octets)."
        )

    try:
        key = base64.b64decode(key_b64)
    except Exception as e:
        raise RuntimeError(f"{ENV_KEY_NAME} n'est pas une Base64 valide.") from e

    if len(key) != SecretBox.KEY_SIZE:
        raise RuntimeError(
            f"Clé invalide: {len(key)} octets (attendu {SecretBox.KEY_SIZE}). "
            "Regénère une clé (32 bytes) et mets-la en Base64."
        )

    return SecretBox(key)


def encrypt_file(input_path: str, output_path: str) -> None:
    """
    Chiffre un fichier avec SecretBox.
    Le format écrit est celui de PyNaCl: nonce + ciphertext + MAC (tout en binaire).
    """
    box = get_box_from_env()

    with open(input_path, "rb") as f:
        plaintext = f.read()

    nonce = nacl.utils.random(SecretBox.NONCE_SIZE)
    encrypted = box.encrypt(plaintext, nonce)  # contient nonce + ciphertext + mac

    with open(output_path, "wb") as f:
        f.write(bytes(encrypted))


def decrypt_file(input_path: str, output_path: str) -> None:
    """
    Déchiffre un fichier SecretBox (nonce+ciphertext+MAC).
    Si le fichier a été modifié ou la clé est fausse -> CryptoError.
    """
    box = get_box_from_env()

    with open(input_path, "rb") as f:
        blob = f.read()

    try:
        plaintext = box.decrypt(blob)
    except CryptoError as e:
        raise RuntimeError("Déchiffrement impossible: données altérées ou clé incorrecte.") from e

    with open(output_path, "wb") as f:
        f.write(plaintext)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Chiffrement/Déchiffrement de fichiers avec PyNaCl SecretBox (clé via GitHub secret)."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_enc = sub.add_parser("encrypt", help="Chiffrer un fichier")
    p_enc.add_argument("input", help="Fichier source")
    p_enc.add_argument("output", help="Fichier chiffré (sortie)")

    p_dec = sub.add_parser("decrypt", help="Déchiffrer un fichier")
    p_dec.add_argument("input", help="Fichier chiffré (source)")
    p_dec.add_argument("output", help="Fichier déchiffré (sortie)")

    args = parser.parse_args()

    if args.cmd == "encrypt":
        encrypt_file(args.input, args.output)
        print(f"OK: {args.input} -> {args.output}")
    else:
        decrypt_file(args.input, args.output)
        print(f"OK: {args.input} -> {args.output}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print(f"ERREUR: {e}", file=sys.stderr)
        raise SystemExit(1)