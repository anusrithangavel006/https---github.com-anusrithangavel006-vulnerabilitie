import argparse
import base64
import os
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken

KEY_FILE = Path("vulncentral.key")

def load_key():
    if not KEY_FILE.exists():
        raise SystemExit(f"Key file {KEY_FILE} not found. Run: python encryption_tool.py generate-key")
    return KEY_FILE.read_bytes().strip()

def main():
    parser = argparse.ArgumentParser(description="Fernet authenticated text encryption demo.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("generate-key")
    enc = sub.add_parser("encrypt")
    enc.add_argument("text")
    dec = sub.add_parser("decrypt")
    dec.add_argument("token")
    args = parser.parse_args()

    if args.command == "generate-key":
        if KEY_FILE.exists():
            raise SystemExit(f"{KEY_FILE} already exists; back it up securely before replacing.")
        KEY_FILE.write_bytes(Fernet.generate_key())
        try:
            os.chmod(KEY_FILE, 0o600)
        except OSError:
            pass
        print(f"Key created at {KEY_FILE.resolve()}. Keep it secret and back it up securely.")
    elif args.command == "encrypt":
        token = Fernet(load_key()).encrypt(args.text.encode("utf-8"))
        print(token.decode("ascii"))
    elif args.command == "decrypt":
        try:
            plaintext = Fernet(load_key()).decrypt(args.token.encode("ascii"))
            print(plaintext.decode("utf-8"))
        except (InvalidToken, UnicodeError):
            raise SystemExit("Decryption failed: invalid token or wrong key.")

if __name__ == "__main__":
    main()
