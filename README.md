## Directory Encryptor (specifically for Parrot os)

A simple **directory encryptor** written in Python for Parrot OS (and other Linux systems).
It lets you turn any folder into a single encrypted file using a password that is **not shown on screen** when you type it.

### 1. Features 

- **Encrypt a directory** into one `.enc` file stored next to the original folder.
- **Decrypt an encrypted file** back into a normal directory.
- **Password-based encryption** (you remember the password, the tool derives a strong key).
- **Rate limiting protection**: Maximum 5 failed decryption attempts per hour per file to prevent brute-force attacks.
- **Interactive menu** for simple usage.
- **Non-interactive CLI mode** with `--encrypt` and `--decrypt` flags for scripting.

### 2. Requirements

- Python **3.10+** (recommended on Parrot OS).
- The Python `cryptography` package.

Install requirements (recommended: use a virtual environment, but not required):

```bash
git clone https://github.com/ze-crossed/dir_Encryptor.git 
cd dir_Encryptor
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If you do not want a virtual environment, just run:

```bash
cd dir_Encryptor
pip install -r requirements.txt
```

### 3. Basic Usage (Menu Mode)

From the project folder:

```bash
cd dir_Encryptor
python3 file_Encryptor.py
```

You will see a menu like:

```text
=== Parrot OS Directory Encryptor ===
1) Encrypt a directory
2) Decrypt an encrypted file
3) Exit
```

#### 3.1 Encrypt a directory

1. Choose option **1**.
2. **Enter directory path to encrypt**  
   - Example: `/home/parrotuser/Documents/secret_stuff`
3. **Enter password (hidden) and confirm it**  
   - The characters will **not be printed** while you type.
4. **Enter encrypted file name**  
   - Only the name, not the path.  
   - Example: `secret_backup.enc`  
   - If you leave this blank, the script uses your folder name + `.enc`.
5. The tool creates the encrypted file **in the same parent folder** as your original directory.

Example:

- Directory: `/home/parrotuser/Documents/secret_stuff`
- Parent folder: `/home/parrotuser/Documents`
- Encrypted file created: `/home/parrotuser/Documents/secret_backup.enc`

#### 3.2 Decrypt an encrypted file

1. Choose option **2**.
2. **Enter encrypted file path**  
   - Example: `/home/parrotuser/Documents/secret_backup.enc`
3. **Enter password**  
   - Must be the same password you used when encrypting.
   - **Note**: After 5 failed password attempts, you must wait 1 hour before trying again (rate limiting protection).
4. **Enter output directory** (or leave blank)  
   - If you leave it blank, files are extracted where the encrypted file is located.

### 4. Non-interactive CLI Usage



## Advance options
You can also run the tool **without the menu**, which is useful for scripts or automation.

#### 4.1 Non-interactive encrypt

```bash
python3 file_Encryptor.py \
  --encrypt /path/to/directory \
  --output-name mybackup.enc \
  --password-env ENC_PASSWORD
```

- **`--encrypt DIR`**: directory to encrypt.
- **`--output-name NAME`** (optional): encrypted filename (no path).  
  - Default: `<directory_name>.enc`, stored in the parent directory of `DIR`.
- **Password source (choose one)**:
  - `--password-env VAR`: read password from environment variable `VAR`.
  - `--password-file FILE`: read the **first line** of `FILE` as the password.
  - `--password-stdin`: read the **first line** from standard input.
  - If none of these are given, it will fall back to an **interactive hidden prompt**.

Example with environment variable:

```bash
export ENC_PASSWORD="my_secret_password"
python3 file_Encryptor.py \
  --encrypt "/home/parrotuser/Documents/secret_stuff" \
  --output-name secret_backup.enc \
  --password-env ENC_PASSWORD
```

#### 4.2 Non-interactive decrypt

```bash
python3 file_Encryptor.py \
  --decrypt /path/to/file.enc \
  --output-dir /path/to/restore/here \
  --password-env ENC_PASSWORD
```

- **`--decrypt FILE`**: encrypted file to decrypt.
- **`--output-dir DIR`** (optional): where to restore the directory.  
  - Default: same folder where the encrypted file lives.
- Password source options are the same as for `--encrypt`.

Example using stdin:

```bash
printf 'my_secret_password\n' | python3 file_Encryptor.py \
  --decrypt "/home/parrotuser/Documents/secret_backup.enc" \
  --output-dir "/home/parrotuser/restore_here" \
  --password-stdin
```

### 5. Security Features

- **Rate Limiting**: To protect against brute-force attacks, the tool limits decryption attempts to 5 per hour per encrypted file. After exceeding this limit, you must wait until the time window expires before trying again.
- **Strong Encryption**: Uses PBKDF2-HMAC-SHA256 with 390,000 iterations to derive encryption keys from passwords.
- **No Password Storage**: Passwords are never stored; they are only used temporarily to derive encryption keys.

### 6. Notes and Limitations

- If you **forget the password**, your data **cannot be recovered**.
- Large directories will take more time and memory because they are compressed before encryption.
- The current version is designed for **personal use** and **local directories**, not network paths.
- Rate limiting files (`.decrypt_attempts_*.json`) are automatically created and managed by the tool. They can be safely deleted if you want to reset the rate limit, but this is not recommended for security reasons.

### 6. Running on Parrot OS

On Parrot OS you typically already have Python 3 installed.

Quick start:

```bash
cd dir_Encryptor
pip install -r requirements.txt
python3 file_Encryptor.py
```

### v2 of this program will use the custom encryption 
