# Subsembly Wallet4 (.wlt) Decryption Tool

Decrypt password manager files created by **[Subsembly Wallet4 / Wallet 4A](https://banking4.de/wallet4.html)**.

If you have a `.wlt` file and know the password, this tool decrypts and displays all stored entries (logins, passwords, notes, etc.).

## How it works

The encryption was reverse-engineered from the .NET DLLs inside the Wallet 4A Android APK.

```
                    ┌──────────────────────────────────┐
                    │          .wlt File (SubFS)        │
                    │  ┌────────┬─────┬─────┬────────┐ │
                    │  │ Header │ FAT │ Dir │ Data…  │ │
                    │  └───┬────┴─────┴─────┴───┬────┘ │
                    └──────┼────────────────────┼──────┘
                           │                    │
                  EncryptedCipherKey        Encrypted
                     + Salt/SaltCrypt       AES-256-ECB
                           │                    │
  Password ──┐             │                    │
             ▼             ▼                    ▼
  ┌─────────────────┐  ┌────────┐         ┌──────────┐
  │ RIPEMD-160 Hash │  │Verify: │         │ Decrypt  │
  │ + XOR extension │──│Salt == │         │ data     │
  │ → 32-byte       │  │Decrypt │         │ clusters │
  │   PassKey        │  │(Salt   │         │ with     │
  └────────┬─────────┘  │ Crypt)?│         │CipherKey │
           │            └────┬───┘         └────┬─────┘
           │                 │OK                │
           ▼                 ▼                  │
     ┌───────────────────────────┐              │
     │ Decrypt CipherKey         │──────────────┘
     │ from header with PassKey  │
     └───────────────────────────┘
```

## Installation

```bash
pip install pycryptodome
```

## Usage

```bash
python3 decrypt_wallet.py <file.wlt> <password>
```

### Example output

```
Password verified OK!

============================================================
WALLET CONTENTS
============================================================

Folder Structure:
  - Allgemein
  - Finanzen
  - E-Mail
  - Shopping
  - Reise

────────────────────────────────────────────────────────────
Schema: Internet Login
GUID:   {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
Fields:
  - Title                [Text]
  - URL                  [URL]
  - Username             [Text]
  - Password             [Password ***]
  - E-Mail               [EMail]
  - Notes                [Multiline]

============================================================
SUMMARY
============================================================
File:        Wallet.wlt
Cipher:      AES-256-ECB
Records:     3
Schemas:     5
```

## File format documentation

See **[Subsembly_Wallet4_WLT_Format.md](Subsembly_Wallet4_WLT_Format.md)** for the full reverse-engineered specification of the `.wlt` container format, including:

- SubFS header layout with byte offsets
- FAT (File Allocation Table) structure
- Key derivation algorithm (RIPEMD-160 + XOR accumulation)
- Two-key encryption system (PassKey / CipherKey)
- Data record format (XML schemas + WalletRecord entries)

## Limitations

- Only supports `.wlt` files (SubFS container format with `SUB\x01` magic header)
- Does **not** support the newer `.wallet` format (fully encrypted, different structure)
- Requires the correct password — there is no password recovery

## What is Subsembly Wallet4?

[Subsembly Wallet4](https://banking4.de/wallet4.html) (also known as **Wallet 4A** on Android) is a password manager by Subsembly GmbH (Munich, Germany). It stores passwords, logins, credit card details, and notes in encrypted `.wlt` files.

The app is no longer actively maintained, which means users may be locked out of their own data if they lose access to the app but still have the `.wlt` file and know their password.

## License

MIT

---

# Deutsche Version

## Subsembly Wallet4 (.wlt) Entschlüsselungstool

Entschlüsselt Passwort-Manager-Dateien von **[Subsembly Wallet4 / Wallet 4A](https://banking4.de/wallet4.html)**.

### Installation

```bash
pip install pycryptodome
```

### Verwendung

```bash
python3 decrypt_wallet.py <datei.wlt> <passwort>
```

### Hintergrund

Die Verschlüsselung wurde durch Reverse Engineering der .NET-DLLs aus dem Wallet 4A Android APK rekonstruiert. Das Tool entschlüsselt die Daten und zeigt alle gespeicherten Einträge an (Logins, Passwörter, Notizen etc.).

Die vollständige technische Dokumentation des `.wlt`-Dateiformats findet sich in **[Subsembly_Wallet4_WLT_Format.md](Subsembly_Wallet4_WLT_Format.md)**.

### Einschränkungen

- Unterstützt nur `.wlt`-Dateien (SubFS-Container mit `SUB\x01`-Header)
- Das neuere `.wallet`-Format wird **nicht** unterstützt
- Das korrekte Passwort wird benötigt — es gibt keine Passwort-Wiederherstellung
