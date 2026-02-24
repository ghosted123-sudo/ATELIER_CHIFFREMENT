#!/usr/bin/env python3
import argparse
import os
import sys
from cryptography.fernet import Fernet, InvalidToken


ENV_KEY_NAME = "FERNET_KEY"


def load_fernet_from_env() -> Fernet:
    key = os.environ.get(ENV_KEY_NAME)
    if not key:
        raise RuntimeError(
            f"Variable d'environnement {ENV_KEY_NAME} manquante. "
            f"Ajoute un Codespaces Secret nommé {ENV_KEY_NAME}."
        )

    # Fernet accepte bytes ou str base64url-safe
    try:
        key_bytes = key.encode("utf-8")
        return Fernet(key_bytes)
    except Exception as e:
        raise RuntimeError(
            f"Clé Fernet invalide dans {ENV_KEY_NAME}. "
            f"Attendu: clé Fernet Base64 (ex: Fernet.generate_key())."
        ) from e


def encrypt_file(in_path: str, out_path: str) -> None:
    f = load_fernet_from_env()
    with open(in_path, "rb") as fin:
        data = fin.read()
    token = f.encrypt(data)
    with open(out_path, "wb") as fout:
        fout.write(token)


def decrypt_file(in_path: str, out_path: str) -> None:
    f = load_fernet_from_env()
    with open(in_path, "rb") as fin:
        token = fin.read()
    try:
        data = f.decrypt(token)
    except InvalidToken as e:
        raise RuntimeError(
            "Déchiffrement impossible: token invalide (clé incorrecte ou fichier modifié)."
        ) from e
    with open(out_path, "wb") as fout:
        fout.write(data)


def main() -> int:
    parser = argparse.ArgumentParser(description="Chiffrement/Déchiffrement de fichiers via Fernet (clé via GitHub Secret).")
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