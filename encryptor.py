import argparse
import getpass
import json
import os
import sys
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


SALT_SIZE = 16  # bytes
KDF_ITERATIONS = 390000
MAX_DECRYPT_ATTEMPTS = 5  # Maximum failed decryption attempts
RATE_LIMIT_WINDOW = 3600  # Time window in seconds (1 hour)


@dataclass
class EncryptionResult:
    encrypted_path: Path
    original_dir: Path


def build_key(password: str, salt: bytes) -> bytes:
    """
    Create a urlsafe base64 key from password+salt using PBKDF2-HMAC.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    key = kdf.derive(password.encode("utf-8"))

    import base64

    # Fernet expects a base64-encoded 32-byte key
    return base64.urlsafe_b64encode(key)


def get_rate_limit_file_path(encrypted_file: Path) -> Path:
    """
    Get the path to the rate limit tracking file for a given encrypted file.
    Uses a hidden file in the same directory as the encrypted file.
    """
    # Create a safe filename based on the encrypted file path
    import hashlib
    file_hash = hashlib.sha256(str(encrypted_file.resolve()).encode()).hexdigest()[:16]
    return encrypted_file.parent / f".decrypt_attempts_{file_hash}.json"


def check_rate_limit(encrypted_file: Path) -> tuple[bool, float | None]:
    """
    Check if the encrypted file has exceeded the rate limit.
    
    Returns:
        (is_allowed, time_until_reset): 
        - is_allowed: True if decryption is allowed, False if rate limited
        - time_until_reset: Seconds until the oldest attempt expires (None if allowed)
    """
    rate_limit_file = get_rate_limit_file_path(encrypted_file)
    current_time = time.time()
    
    # If no rate limit file exists, allow the attempt
    if not rate_limit_file.exists():
        return (True, None)
    
    try:
        with rate_limit_file.open("r") as f:
            data = json.load(f)
            attempts = data.get("attempts", [])
    except (json.JSONDecodeError, KeyError, OSError):
        # If file is corrupted, treat as no attempts
        return (True, None)
    
    # Filter out attempts older than the rate limit window
    recent_attempts = [
        attempt_time
        for attempt_time in attempts
        if current_time - attempt_time < RATE_LIMIT_WINDOW
    ]
    
    # Update the file with only recent attempts
    if len(recent_attempts) != len(attempts):
        try:
            with rate_limit_file.open("w") as f:
                json.dump({"attempts": recent_attempts}, f)
        except OSError:
            pass  # If we can't write, continue anyway
    
    # Check if we've exceeded the limit
    if len(recent_attempts) >= MAX_DECRYPT_ATTEMPTS:
        # Calculate time until the oldest attempt expires
        oldest_attempt = min(recent_attempts)
        time_until_reset = RATE_LIMIT_WINDOW - (current_time - oldest_attempt)
        return (False, time_until_reset)
    
    return (True, None)


def record_failed_attempt(encrypted_file: Path) -> None:
    """
    Record a failed decryption attempt for rate limiting.
    """
    rate_limit_file = get_rate_limit_file_path(encrypted_file)
    current_time = time.time()
    
    # Load existing attempts
    if rate_limit_file.exists():
        try:
            with rate_limit_file.open("r") as f:
                data = json.load(f)
                attempts = data.get("attempts", [])
        except (json.JSONDecodeError, KeyError, OSError):
            attempts = []
    else:
        attempts = []
    
    # Filter out old attempts (older than rate limit window)
    attempts = [
        attempt_time
        for attempt_time in attempts
        if current_time - attempt_time < RATE_LIMIT_WINDOW
    ]
    
    # Add the new failed attempt
    attempts.append(current_time)
    
    # Save updated attempts
    try:
        with rate_limit_file.open("w") as f:
            json.dump({"attempts": attempts}, f)
        # Set restrictive permissions (owner read/write only)
        try:
            rate_limit_file.chmod(0o600)
        except OSError:
            pass  # Ignore if chmod fails
    except OSError:
        pass  # If we can't write, continue anyway


def clear_rate_limit(encrypted_file: Path) -> None:
    """
    Clear rate limit tracking for a successful decryption.
    """
    rate_limit_file = get_rate_limit_file_path(encrypted_file)
    if rate_limit_file.exists():
        try:
            rate_limit_file.unlink()
        except OSError:
            pass  # Ignore if deletion fails


def encrypt_directory(directory: Path, password: str, output_name: str) -> EncryptionResult:
    """
    Create a tar archive of the directory in memory, then encrypt it with a password.
    The resulting file is stored next to the directory.
    """
    if not directory.is_dir():
        raise ValueError(f"{directory} is not a directory")

    parent = directory.parent
    if not output_name:
        output_name = directory.name + ".enc"

    if not output_name.endswith(".enc"):
        output_name = output_name + ".enc"

    encrypted_path = parent / output_name

    import io
    import os as _os

    # Create tar archive in memory
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(str(directory), arcname=directory.name)
    data = buf.getvalue()

    # Derive key and encrypt
    salt = _os.urandom(SALT_SIZE)
    key = build_key(password, salt)
    f = Fernet(key)
    token = f.encrypt(data)

    # Format: [magic bytes][salt][ciphertext]
    magic = b"PARROTENC1"
    with encrypted_path.open("wb") as f_out:
        f_out.write(magic)
        f_out.write(salt)
        f_out.write(token)

    return EncryptionResult(encrypted_path=encrypted_path, original_dir=directory)


def decrypt_file(encrypted_file: Path, password: str, output_dir: Path | None = None) -> Path:
    """
    Decrypt an encrypted archive file and extract it into output_dir (or alongside the file).
    Includes rate limiting: maximum 5 failed attempts per hour per file.
    """
    if not encrypted_file.is_file():
        raise ValueError(f"{encrypted_file} is not a file")

    # Check rate limit before attempting decryption
    is_allowed, time_until_reset = check_rate_limit(encrypted_file)
    if not is_allowed:
        hours = int(time_until_reset // 3600)
        minutes = int((time_until_reset % 3600) // 60)
        seconds = int(time_until_reset % 60)
        if hours > 0:
            time_str = f"{hours} hour(s), {minutes} minute(s)"
        elif minutes > 0:
            time_str = f"{minutes} minute(s), {seconds} second(s)"
        else:
            time_str = f"{seconds} second(s)"
        raise ValueError(
            f"Rate limit exceeded: Too many failed decryption attempts. "
            f"Please wait {time_str} before trying again. "
            f"(Maximum {MAX_DECRYPT_ATTEMPTS} attempts per hour)"
        )

    try:
        with encrypted_file.open("rb") as f_in:
            magic = f_in.read(len(b"PARROTENC1"))
            if magic != b"PARROTENC1":
                raise ValueError("Not a valid encrypted file format")
            salt = f_in.read(SALT_SIZE)
            token = f_in.read()

        key = build_key(password, salt)
        f = Fernet(key)
        data = f.decrypt(token)

        import io

        buf = io.BytesIO(data)
        if output_dir is None:
            output_dir = encrypted_file.parent

        with tarfile.open(fileobj=buf, mode="r:gz") as tar:
            tar.extractall(path=output_dir)

        # Clear rate limit on successful decryption
        clear_rate_limit(encrypted_file)
        return output_dir

    except InvalidToken:
        # Wrong password - record failed attempt for rate limiting
        record_failed_attempt(encrypted_file)
        raise ValueError("Decryption failed: Invalid password or corrupted data")
    except Exception as e:
        # Other errors (file format, tar extraction, etc.) - don't count as password failures
        raise


def prompt_password() -> str:
    while True:
        pwd1 = getpass.getpass("Enter password (will not be shown): ")
        pwd2 = getpass.getpass("Confirm password: ")
        if pwd1 != pwd2:
            print("Passwords do not match. Please try again.\n")
            continue
        if not pwd1:
            print("Password cannot be empty. Please try again.\n")
            continue
        return pwd1


def get_password_from_sources(
    password_env: str | None,
    password_file: str | None,
    password_stdin: bool,
    confirm: bool,
) -> str:
    """
    Resolve a password for non-interactive modes.

    Priority:
      1. Environment variable via --password-env
      2. File via --password-file (first line)
      3. Standard input via --password-stdin (first line)
      4. Fallback to interactive prompt (with optional confirmation)
    """
    # 1) Environment variable
    if password_env:
        value = os.environ.get(password_env)
        if value is None:
            raise ValueError(f"Environment variable '{password_env}' is not set")
        return value.rstrip("\n")

    # 2) Password file
    if password_file:
        path = Path(password_file).expanduser()
        if not path.is_file():
            raise ValueError(f"Password file '{path}' does not exist")
        first_line = path.read_text(encoding="utf-8").splitlines()
        if not first_line:
            raise ValueError(f"Password file '{path}' is empty")
        return first_line[0].rstrip("\n")

    # 3) Standard input
    if password_stdin:
        line = sys.stdin.readline()
        if not line:
            raise ValueError("No password received from standard input")
        return line.rstrip("\n")

    # 4) Fallback to interactive prompt
    if confirm:
        return prompt_password()
    return getpass.getpass("Enter password (will not be shown): ")


def main_menu() -> None:
    print("=== Parrot OS Directory Encryptor ===")
    print("1) Encrypt a directory")
    print("2) Decrypt an encrypted file")
    print("3) Exit")

    choice = input("Choose an option (1-3): ").strip()
    if choice == "1":
        handle_encrypt()
    elif choice == "2":
        handle_decrypt()
    elif choice == "3":
        print("Goodbye.")
    else:
        print("Invalid choice.")


def handle_encrypt() -> None:
    raw_path = input("Enter directory path to encrypt: ").strip()
    directory = Path(raw_path).expanduser().resolve()

    if not directory.is_dir():
        print(f"Path '{directory}' is not a directory or does not exist.")
        return

    password = prompt_password()
    output_name = input(
        "Enter encrypted file name (without path, e.g. mybackup.enc). Leave blank to use directory name: "
    ).strip()

    try:
        result = encrypt_directory(directory, password, output_name)
    except Exception as e:
        print(f"Error during encryption: {e}")
        return

    print(f"\nDirectory encrypted successfully!")
    print(f"Original directory : {result.original_dir}")
    print(f"Encrypted file     : {result.encrypted_path}")


def handle_decrypt() -> None:
    raw_path = input("Enter encrypted file path (.enc): ").strip()
    encrypted_file = Path(raw_path).expanduser().resolve()

    if not encrypted_file.is_file():
        print(f"File '{encrypted_file}' does not exist.")
        return

    password = getpass.getpass("Enter password (will not be shown): ")
    output_dir_input = input(
        "Enter output directory (leave blank to use same folder as encrypted file): "
    ).strip()
    output_dir = (
        Path(output_dir_input).expanduser().resolve()
        if output_dir_input
        else encrypted_file.parent
    )

    try:
        dest = decrypt_file(encrypted_file, password, output_dir)
    except Exception as e:
        print(f"Error during decryption: {e}")
        return

    print(f"\nEncrypted file decrypted successfully!")
    print(f"Output directory: {dest}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Simple password-based directory encryptor for Parrot OS."
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--encrypt",
        metavar="DIR",
        help="Encrypt the given directory (non-interactive mode).",
    )
    mode_group.add_argument(
        "--decrypt",
        metavar="FILE",
        help="Decrypt the given encrypted file (non-interactive mode).",
    )

    parser.add_argument(
        "--output-name",
        help="Output encrypted filename (no path) for --encrypt mode. "
        "Defaults to <directory>.enc.",
    )
    parser.add_argument(
        "--output-dir",
        help="Destination directory for --decrypt mode. "
        "Defaults to the directory of the encrypted file.",
    )

    parser.add_argument(
        "--password-env",
        help="Name of environment variable that contains the password.",
    )
    parser.add_argument(
        "--password-file",
        help="Path to a file whose first line is the password.",
    )
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read password from standard input (first line).",
    )

    args = parser.parse_args(argv)

    # Non-interactive encrypt mode
    if args.encrypt:
        directory = Path(args.encrypt).expanduser().resolve()
        try:
            password = get_password_from_sources(
                args.password_env,
                args.password_file,
                args.password_stdin,
                confirm=False,
            )
        except ValueError as e:
            print(f"Password error: {e}")
            sys.exit(1)

        try:
            result = encrypt_directory(directory, password, args.output_name or "")
        except Exception as e:
            print(f"Encryption failed: {e}")
            sys.exit(1)

        print(f"Encrypted file created at: {result.encrypted_path}")
        return

    # Non-interactive decrypt mode
    if args.decrypt:
        encrypted_file = Path(args.decrypt).expanduser().resolve()
        output_dir = (
            Path(args.output_dir).expanduser().resolve()
            if args.output_dir
            else encrypted_file.parent
        )
        try:
            password = get_password_from_sources(
                args.password_env,
                args.password_file,
                args.password_stdin,
                confirm=False,
            )
        except ValueError as e:
            print(f"Password error: {e}")
            sys.exit(1)

        try:
            dest = decrypt_file(encrypted_file, password, output_dir)
        except Exception as e:
            print(f"Decryption failed: {e}")
            sys.exit(1)

        print(f"Decrypted content extracted to: {dest}")
        return

    main_menu()


if __name__ == "__main__":
    main()

