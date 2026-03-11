#!/usr/bin/env python3
"""
Subsembly Wallet4 (.wlt) Decryption Tool
Reverse-engineered from Subsembly.SubFS.dll and Subsembly.Crypto.dll

Usage: python3 decrypt_wallet.py <file.wlt> <password>

Encryption: AES-256-ECB with custom key derivation
  1. RIPEMD-160(static_constant + password_utf16le) → 20-byte hash
  2. Running XOR accumulation to extend to 32-byte AES key
  3. PassKey decrypts CipherKey from header
  4. CipherKey decrypts data pages
"""

import struct
import sys
import re
import os
from Crypto.Cipher import AES
from Crypto.Hash import RIPEMD160


# Static constant extracted from Subsembly.SubFS.dll FieldRVA (field 138)
STATIC_CONST = bytes.fromhex(
    '903c4a1640b44381b199866aa4516d19'
    '0cb0dcb8efa14c1a97ce043b341a34cf'
)

CLUSTER_SIZE = 512


def derive_pass_key(password):
    """Derive the 32-byte PassKey from the password string."""
    password_bytes = password.encode('utf-16-le')
    h = RIPEMD160.new()
    h.update(STATIC_CONST + password_bytes)
    hash_result = h.digest()  # 20 bytes

    # Running XOR accumulation: extend 20 bytes → 32 bytes
    pass_key = bytearray(32)
    acc = 0
    hash_len = len(hash_result)
    for i in range(32):
        acc = (acc ^ hash_result[i % hash_len]) & 0xFF
        pass_key[i] = acc

    return bytes(pass_key)


def decrypt_ecb(key, data):
    """Decrypt data using AES-256-ECB."""
    cipher = AES.new(key, AES.MODE_ECB)
    result = bytearray()
    for i in range(0, len(data), 16):
        result.extend(cipher.decrypt(data[i:i+16]))
    return bytes(result)


def decrypt_wallet(filepath, password):
    """Decrypt a Subsembly Wallet4 .wlt file."""
    with open(filepath, 'rb') as f:
        file_data = f.read()

    # Validate header
    if file_data[:4] != b'SUB\x01':
        print("ERROR: Not a Subsembly Wallet file (missing SUB\\x01 header)")
        return False

    cluster_size = struct.unpack_from('<I', file_data, 4)[0]
    cipher_type = struct.unpack_from('<I', file_data, 0x14)[0]
    pass_iterations = struct.unpack_from('<I', file_data, 0x18)[0]
    sec_flags = struct.unpack_from('<I', file_data, 0x10)[0]
    salt = file_data[0x1C:0x1C+32]
    salt_crypt = file_data[0x3C:0x3C+32]

    if cipher_type != 3:
        print(f"WARNING: Cipher type {cipher_type} (expected 3=AES-256)")

    # Step 1: Derive PassKey
    pass_key = derive_pass_key(password)

    # Step 2: Verify password
    decrypted_salt = decrypt_ecb(pass_key, salt_crypt)
    if decrypted_salt != salt:
        print("ERROR: Wrong password!")
        return False

    print("Password verified OK!")
    print()

    # Step 3: Decrypt CipherKey from header
    encrypted_cipher_key = file_data[0x100:0x100+32]
    cipher_key = decrypt_ecb(pass_key, encrypted_cipher_key)

    # Step 4: Parse FAT (page allocation table at cluster 1)
    num_clusters = len(file_data) // cluster_size
    fat = {}
    for i in range(num_clusters):
        entry_off = cluster_size + i * 4  # FAT at cluster 1
        if entry_off + 4 > len(file_data):
            break
        raw = struct.unpack_from('<I', file_data, entry_off)[0]
        flag = raw & 0xFF
        next_cluster = (raw >> 8) & 0xFFFFFF
        if flag == 0xFF:
            fat[i] = -1  # end of chain
        elif flag == 0x01:
            fat[i] = next_cluster
        else:
            fat[i] = None  # free

    def follow_chain(start):
        chain = [start]
        current = start
        while current in fat and fat[current] not in (None, -1):
            current = fat[current]
            chain.append(current)
            if len(chain) > 200:
                break
        return chain

    # Step 5: Parse record index (directory at cluster 2)
    dir_offset = 2 * cluster_size
    dir_data = file_data[dir_offset:dir_offset+cluster_size]
    records = {}
    entry_size = 64

    for i in range(cluster_size // entry_size):
        entry = dir_data[i*entry_size:(i+1)*entry_size]
        page = struct.unpack_from('<I', entry, 0)[0]
        size = struct.unpack_from('<I', entry, 4)[0]
        keylen = entry[9]
        if keylen == 0 or keylen >= 60 or size == 0:
            continue
        key = entry[10:10+keylen].decode('utf-8', errors='replace').rstrip('\x00')
        records[key] = (page, size)

    # Step 6: Decrypt and display all records
    def decrypt_cluster_chain(chain):
        decrypted = bytearray()
        for page in chain:
            offset = page * cluster_size
            encrypted = file_data[offset:offset+cluster_size]
            decrypted.extend(decrypt_ecb(cipher_key, encrypted))
        return bytes(decrypted)

    # Collect all folder tree data and XML schemas
    all_decrypted = {}
    for key, (page, size) in records.items():
        if key == '_Folders':
            continue
        chain = follow_chain(page)
        dec = decrypt_cluster_chain(chain)[:size]
        all_decrypted[key] = dec

    # Also get the _Folders continuation data (encrypted page in chain)
    folders_page, folders_size = records.get('_Folders', (None, None))
    folders_chain = follow_chain(folders_page) if folders_page else []

    # The folder tree is stored at the start of the first data record
    # It uses ASCII control chars as delimiters (US=0x1F, RS=0x1E)
    # and ends where the XML schemas begin (second BOM marker)
    folder_tree_text = ""
    for key, dec in all_decrypted.items():
        try:
            text = dec.decode('utf-8', errors='replace')
        except:
            continue
        if '\x1f' in text and '\x1e' in text:
            bom_pos = text.find('\ufeff')
            if bom_pos >= 0:
                # Find end: either next BOM (XML schema start) or null padding
                rest = text[bom_pos+1:]
                second_bom = rest.find('\ufeff')
                null_pos = rest.find('\x00')
                if second_bom > 0 and (null_pos == -1 or second_bom < null_pos):
                    folder_tree_text = rest[:second_bom]
                elif null_pos > 0:
                    folder_tree_text = rest[:null_pos]
                else:
                    folder_tree_text = rest
            break

    # Parse folder tree
    print("=" * 60)
    print("WALLET CONTENTS")
    print("=" * 60)

    if folder_tree_text:
        # Check if folder tree is cut off (no trailing RS/null)
        # and get continuation from encrypted pages in _Folders chain
        if not folder_tree_text.endswith('\x1e') and not folder_tree_text.endswith('\x00'):
            for pg in folders_chain:
                if pg == 2:  # skip directory page (plaintext)
                    continue
                dec_pg = decrypt_cluster_chain([pg])
                try:
                    cont = dec_pg.decode('utf-8', errors='replace')
                    null_pos = cont.find('\x00')
                    if null_pos > 0:
                        cont = cont[:null_pos]
                    folder_tree_text += cont
                except:
                    pass

        entries = folder_tree_text.split('\x1e')
        print("\nFolder Structure:")
        for entry in entries:
            fields = entry.split('\x1f')
            if len(fields) >= 4:
                name = fields[2] if len(fields) > 2 else "?"
                icon = fields[3] if len(fields) > 3 else ""
                schema = fields[5] if len(fields) > 5 else ""
                if name:
                    print(f"  - {name}" + (f" (Schema: {schema})" if schema else ""))

    # Display schemas and look for actual entries
    print()
    schemas = {}
    for key, dec in all_decrypted.items():
        text = dec.decode('utf-8', errors='replace')

        # Find XML sections
        xml_matches = list(re.finditer(r'\ufeff<\?xml[^>]*\?>(.*?)(?=\ufeff|\x00{4,}|$)', text, re.DOTALL))
        if not xml_matches:
            xml_matches = list(re.finditer(r'<\?xml[^>]*\?>(.*?)(?=\ufeff|\x00{4,}|$)', text, re.DOTALL))

        for m in xml_matches:
            xml_content = m.group(0).lstrip('\ufeff')
            # Clean trailing garbage
            last_close = xml_content.rfind('>')
            if last_close > 0:
                xml_content = xml_content[:last_close+1]

            # Extract schema info
            name_m = re.search(r'<Name>([^<]+)</Name>', xml_content)
            guid_m = re.search(r'<GUID>([^<]+)</GUID>', xml_content)
            desc_m = re.search(r'<Description>([^<]+)</Description>', xml_content)

            if guid_m:
                schema_guid = guid_m.group(1)
                schema_name = name_m.group(1) if name_m else "Unknown"
                schema_desc = desc_m.group(1) if desc_m else ""

                print(f"{'─' * 60}")
                print(f"Schema: {schema_name}")
                print(f"GUID:   {schema_guid}")
                if schema_desc:
                    print(f"Info:   {schema_desc[:80]}")

                # Extract fields
                fields = re.findall(r'<Field>(.*?)</Field>', xml_content, re.DOTALL)
                if fields:
                    print(f"Fields:")
                    for field in fields:
                        col = re.search(r'<ColName>([^<]+)', field)
                        cap = re.search(r'<Caption>([^<]+)', field)
                        ftype = re.search(r'<Type>([^<]+)', field)
                        if cap and ftype:
                            type_str = ftype.group(1)
                            if type_str == 'Password':
                                type_str = 'Password ***'
                            print(f"  - {cap.group(1):20s} [{type_str}]")

                schemas[schema_guid] = schema_name
                print()

        # Check for WalletRecord entries (actual data, not just schema)
        record_matches = re.findall(r'<WalletRecord>(.*?)</WalletRecord>', text, re.DOTALL)
        for rec in record_matches:
            print(f"{'─' * 60}")
            print(f"DATA ENTRY FOUND in {key}:")
            # Parse entry fields
            for field_m in re.finditer(r'<(\w+)>([^<]*)</\1>', rec):
                fname = field_m.group(1)
                fval = field_m.group(2)
                if fval:
                    print(f"  {fname}: {fval}")

    if not schemas:
        print("No schemas found in the decrypted data.")

    # Summary
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"File:        {os.path.basename(filepath)}")
    print(f"Cipher:      AES-256-ECB")
    print(f"Records:     {len(records)}")
    print(f"Schemas:     {len(schemas)}")
    actual_entries = sum(1 for dec in all_decrypted.values()
                        if b'<WalletRecord>' in dec)
    if actual_entries:
        print(f"Data entries: {actual_entries}")
    else:
        print(f"Data entries: None (empty wallet - only folder structure and schemas)")

    return True


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <file.wlt> <password>")
        print()
        print("Decrypts Subsembly Wallet4 password manager files.")
        print("Requires: pip install pycryptodome")
        sys.exit(1)

    filepath = sys.argv[1]
    password = sys.argv[2]

    if not os.path.exists(filepath):
        print(f"ERROR: File not found: {filepath}")
        sys.exit(1)

    success = decrypt_wallet(filepath, password)
    sys.exit(0 if success else 1)
