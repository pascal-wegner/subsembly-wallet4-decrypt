# Subsembly Wallet4 (.wlt) - Verschlüsselungsdokumentation

> Reverse-Engineered aus `Subsembly.SubFS.dll` und `Subsembly.Crypto.dll`
> Extrahiert aus dem Android APK: subsembly.wallet (Wallet 4A)
> Erstellt: März 2026

---

## 1. Übersicht

Subsembly Wallet4 ist ein Passwort-Manager der Firma Subsembly GmbH (München).
Die Wallet-Dateien (`.wlt`) verwenden ein proprietäres Container-Format namens
**SubFS** (Sub File System) — ein virtuelles Dateisystem mit eigener Verschlüsselung.

| Eigenschaft | Wert |
|---|---|
| Verschlüsselung | AES-256-ECB (Electronic Codebook Mode) |
| Hash-Algorithmus | RIPEMD-160 |
| Key-Länge | 32 Byte (256 Bit) |
| Cluster-Größe | 512 Byte |
| Schlüsselsystem | Zwei-Schlüssel: PassKey (aus Passwort) + CipherKey (zufällig) |

---

## 2. Dateiformat (SubFS Container)

Die `.wlt`-Datei ist in 512-Byte-Cluster unterteilt:

| Cluster | Inhalt | Verschlüsselt? |
|---|---|---|
| 0 | Header | Nein (Klartext) |
| 1 | FAT (File Allocation Table) | Nein (Klartext) |
| 2 | Verzeichnis (Record Index) | Nein (Klartext) |
| 3+ | Daten-Seiten | Ja (AES-256-ECB mit CipherKey) |

### 2.1 Header (Cluster 0, Offset 0x000–0x1FF)

| Offset | Länge | Feld | Beschreibung |
|---|---|---|---|
| `0x000` | 4 | Magic | `SUB\x01` (Hex: `53 55 42 01`) |
| `0x004` | 4 | ClusterSize | Cluster-Größe in Bytes (512 = `0x0200`) |
| `0x008` | 4 | CreateTimeStamp | Erstellzeit (Sek. seit 01.01.2000 UTC) |
| `0x00C` | 4 | DirCluster | Verzeichnis-Cluster (normalerweise 1) |
| `0x010` | 4 | SecurityFlags | `0x00` = keine, `0x01` = DeviceGuid-gebunden |
| `0x014` | 4 | CipherType | `0`=Keine, `1`=AES-128, `2`=AES-192, `3`=AES-256 |
| `0x018` | 4 | PassIterations | Key-Stretching-Iterationen (`0`=kein Stretching, `100000`=Standard) |
| `0x01C` | 32 | Salt | 32 Byte Zufallsdaten (bei Erstellung generiert) |
| `0x03C` | 32 | SaltCrypt | Salt verschlüsselt mit PassKey (zur Passwort-Verifikation) |
| `0x05C` | 20 | Legacy | Altes Format-Feld (in neuen Dateien = 0) |
| `0x070` | 16 | FileGuid | Eindeutige Datei-ID (GUID) |
| `0x080` | 16 | TypeGuid | Anwendungs-Typ-GUID |
| `0x090` | 4 | FalsePasswordAttempts | Zähler fehlgeschlagener Anmeldungen |
| `0x094` | 32 | TokenSalt | Salt für biometrische Token-Auth |
| `0x0B4` | 32 | TokenTest | Test-Daten für Token-Verifikation |
| `0x0D4` | 4 | ModifyTimeStamp | Letzte Änderung (Sek. seit 01.01.2000) |
| `0x0D8` | 40 | Reserved | Reserviert (Nullen) |
| `0x100` | 256 | EncryptedCipherKey | CipherKey verschlüsselt mit PassKey (nur erste 32 Bytes genutzt bei AES-256, Rest ist Null-Padding) |

**Gesamtgröße Header:** 512 Bytes (1 Cluster)

#### Hex-Dump Beispiel (Wallet.wlt)

```
0x000: 53554201 00020000 dee64231 01000000  SUB.......B1....
0x010: 00000000 03000000 00000000 3c1459db  ............<.Y.
       |SecFlg|  |Cipher|  |Iter=0| |--- Salt (32 Bytes) ---|
0x020: 43b8398e 28b18554 0162bfcd 2c2188d5
0x030: 6ff287c1 b3c88867 1ccecf4f           |--- Salt Ende --|
0x03C:                    98b5df2a 2c0bd1f5  |-- SaltCrypt ---|
0x040: 2b1ac076 88ff9048 c2fc11ec 196b9656
0x050: bf0b41e2 a303ac7c                     |-- SaltCr Ende-|
...
0x100: cb49c281 9c4a5da1 1e1ea11b ca20f5a4  |-- EncCipherKey-|
0x110: 0e686f8e 13648321 8a25f448 29f704aa  |-- EncCK Ende --|
```

### 2.2 FAT — File Allocation Table (Cluster 1)

Die FAT beginnt bei Cluster 1 (Offset `0x200`) und enthält 4-Byte-Einträge
für jeden Cluster:

**Aufbau eines 4-Byte FAT-Eintrags (Little-Endian):**

| Byte | Feld | Werte |
|---|---|---|
| 0 | Flag | `0x00` = Frei, `0x01` = Belegt (nächster Cluster folgt), `0xFF` = Ende der Kette |
| 1–3 | Nächster Cluster | 24-Bit Little-Endian (nur relevant wenn Flag = `0x01`) |

**Beispiele:**

```
0x010300FF → Flag=0xFF (Ende), Nächster=irrelevant
0x04000001 → Flag=0x01 (belegt), Nächster=Cluster 4
```

Bei 512 Byte Cluster-Größe passen 128 FAT-Einträge pro Cluster.

### 2.3 Verzeichnis (Cluster 2)

Das Verzeichnis bei Cluster 2 (Offset `0x400`) enthält 64-Byte-Einträge,
die virtuelle Dateien im Container beschreiben:

| Offset | Länge | Feld |
|---|---|---|
| 0 | 4 | StartCluster — Erster Daten-Cluster |
| 4 | 4 | DataSize — Datengröße in Bytes |
| 8 | 1 | Flags — Datei-Flags |
| 9 | 1 | KeyLength — Länge des Dateinamens |
| 10 | 54 | Key — Dateiname (UTF-8, Null-terminiert) |

Einträge mit `KeyLength=0` oder `DataSize=0` werden übersprungen.

**Typische Einträge:**

- `_Folders` — Ordnerstruktur (ASV-Format)
- `{GUID}` — Schema-Definitionen (XML) und Datensätze

---

## 3. Verschlüsselung

### 3.1 Key-Derivation: Vom Passwort zum PassKey

Das Passwort wird in zwei Schritten in einen 32-Byte AES-Schlüssel (PassKey) umgewandelt:

#### Schritt 1: RIPEMD-160 Hash

```
Eingabe:  StaticConstant (32 Bytes) + Passwort (UTF-16LE kodiert)
Ausgabe:  20-Byte Hash
```

Die StaticConstant ist fest im Code eingebettet (FieldRVA in `SubFS.dll`):

```
90 3C 4A 16 40 B4 43 81 B1 99 86 6A A4 51 6D 19
0C B0 DC B8 EF A1 4C 1A 97 CE 04 3B 34 1A 34 CF
```

**Beispiel für Passwort `"testtest"`:**

```
Passwort UTF-16LE: 74 00 65 00 73 00 74 00 74 00 65 00 73 00 74 00
RIPEMD-160 Input:  [32 Bytes Constant] + [16 Bytes Passwort]
RIPEMD-160 Output: 20 Bytes Hash
```

#### Schritt 2: XOR-Akkumulation (20 → 32 Bytes)

Der 20-Byte RIPEMD-160-Hash wird auf 32 Bytes erweitert:

```python
accumulator = 0
for i in range(32):
    accumulator = accumulator XOR hash[i % 20]
    passKey[i] = accumulator
```

> **Hinweis:** Dieses Verfahren ist kryptographisch schwach — es erzeugt nur
> 12 zusätzliche Bytes durch zyklisches XOR. Die effektive Entropie bleibt
> bei 160 Bit (RIPEMD-160 Output).

### 3.2 Key-Stretching (Optional)

Wenn `PassIterations > 0` (z.B. 100000), wird der PassKey zusätzlich verstärkt:

```
Für jede Iteration i = 0 bis PassIterations-1:
  1. AES-256-ECB initialisieren mit aktuellem PassKey
  2. temp[0..15]  = AES_Encrypt(Salt[0..15])
  3. temp[16..31] = AES_Encrypt(Salt[16..31])
  4. PassKey[j] = PassKey[j] XOR temp[j]  (für j = 0..31)
```

Dies ist eine proprietäre PBKDF-Variante (kein Standard-PBKDF2).
Bei 100.000 Iterationen dauert die Ableitung ca. 0,75 Sekunden.

> **Hinweis:** Die hier dokumentierte `Wallet.wlt` hat `PassIterations=0`,
> d.h. dieses Stretching wird NICHT angewendet.

### 3.3 Passwort-Verifikation

```
1. Salt aus Header lesen       (Offset 0x1C, 32 Bytes)
2. SaltCrypt aus Header lesen  (Offset 0x3C, 32 Bytes)
3. PassKey ableiten (siehe 3.1)
4. AES-256-ECB-Decrypt(SaltCrypt, PassKey) ausführen
5. Ergebnis mit Salt vergleichen

→ Entschlüsseltes == Salt:  Passwort ist KORREKT
→ Entschlüsseltes != Salt:  Passwort ist FALSCH → Abbruch
```

### 3.4 CipherKey-Entschlüsselung

Der CipherKey ist ein zufällig generierter AES-Schlüssel, der bei der
Erstellung der Wallet-Datei erzeugt wird. Er wird verschlüsselt im Header gespeichert:

```
EncryptedCipherKey = Header[0x100 .. 0x11F]  (32 Bytes für AES-256)
CipherKey = AES-256-ECB-Decrypt(EncryptedCipherKey, PassKey)
```

**Zwei-Schlüssel-System:**

| Schlüssel | Herkunft | Lebensdauer |
|---|---|---|
| PassKey | abgeleitet vom Passwort | ändert sich bei Passwort-Änderung |
| CipherKey | zufällig generiert | bleibt gleich (nur Verschlüsselung im Header wird aktualisiert) |

**Vorteil:** Bei Passwort-Änderung müssen die Daten nicht neu verschlüsselt
werden — nur der CipherKey wird mit dem neuen PassKey neu verschlüsselt.

### 3.5 Daten-Verschlüsselung

Daten-Cluster (ab Cluster 3) werden einzeln verschlüsselt:

```
Für jeden 512-Byte Cluster:
  Für jeden 16-Byte Block innerhalb des Clusters:
    plaintext_block = AES-256-ECB-Decrypt(ciphertext_block, CipherKey)
```

AES-ECB verschlüsselt jeden 16-Byte-Block unabhängig:

- Gleiche Klartextblöcke erzeugen gleiche Chiffretextblöcke
- Kein IV (Initialisierungsvektor) nötig
- Keine Verkettung zwischen Blöcken
- Aus kryptographischer Sicht schwächer als AES-CBC/CTR

---

## 4. Entschlüsselungs-Algorithmus (Zusammenfassung)

```
Input: .wlt Datei, Passwort (String)

1. Header prüfen: Offset 0 == "SUB\x01"
2. Header-Felder lesen: ClusterSize, CipherType, PassIterations,
   Salt, SaltCrypt, EncryptedCipherKey
3. PassKey = DerivePassKey(Passwort)
     a) hash = RIPEMD-160(StaticConstant + Passwort_UTF16LE)
     b) XOR-Akkumulation: hash (20 Bytes) → PassKey (32 Bytes)
     c) Falls PassIterations > 0: Key-Stretching mit AES+Salt
4. Verifikation: AES-256-ECB-Decrypt(SaltCrypt, PassKey) == Salt?
5. CipherKey = AES-256-ECB-Decrypt(EncryptedCipherKey, PassKey)
6. FAT lesen (Cluster 1, 4-Byte-Einträge)
7. Verzeichnis lesen (Cluster 2, 64-Byte-Einträge)
8. Für jeden Verzeichnis-Eintrag:
     a) Cluster-Kette über FAT verfolgen
     b) Alle Cluster der Kette mit CipherKey entschlüsseln (AES-256-ECB)
     c) Entschlüsselte Daten auf DataSize zuschneiden
```

---

## 5. Wallet-Datenstruktur (nach Entschlüsselung)

### 5.1 Ordnerstruktur (`_Folders`)

Die Ordnerstruktur wird im ASV-Format (ASCII Separated Values) gespeichert:

**Trennzeichen:**

| Byte | Name | Funktion |
|---|---|---|
| `0x1F` | US (Unit Separator) | trennt Felder innerhalb eines Eintrags |
| `0x1E` | RS (Record Separator) | trennt Einträge |
| `0xFEFF` | BOM | markiert Anfang der Daten |

**Felder pro Eintrag (7 Spalten):**

1. FolderOID — Eindeutige Ordner-ID
2. ParentFolderOID — Übergeordneter Ordner
3. Name — Anzeigename des Ordners
4. IconName — Icon-Bezeichnung
5. ObjectType — Objekttyp
6. SchemaGUID — Zugeordnetes Schema
7. TableGUID — Zugeordnete Datentabelle

### 5.2 Schema-Definitionen (XML)

Schemata definieren die Felder für verschiedene Eintragstypen (z.B. Login,
Kreditkarte, Bankverbindung). Sie sind als XML im Container gespeichert:

```xml
<?xml version="1.0" encoding="utf-8"?>
<WalletSchema>
  <GUID>{...}</GUID>
  <Name>Schema-Name</Name>
  <Description>Beschreibung</Description>
  <Fields>
    <Field>
      <ColName>spaltenname</ColName>
      <Caption>Anzeigename</Caption>
      <Type>Feldtyp</Type>
    </Field>
  </Fields>
</WalletSchema>
```

**Feldtypen:** `Text`, `Password`, `Number`, `Decimal`, `Choice`, `Date`,
`SubHeader`, `Token`, `Multiline`, `URL`, `Phone`, `EMail`

> **Hinweis:** `Password`-Felder sind nur ein Anzeige-Typ (werden in der App
> als Sternchen angezeigt). Es gibt keine Feld-Level-Verschlüsselung —
> alle Felder werden gleich behandelt.

### 5.3 Datensätze (WalletRecord)

Eigentliche Passwort-Einträge werden als XML gespeichert:

```xml
<WalletRecord>
  <Name>Eintrag-Name</Name>
  <Username>benutzername</Username>
  <Password>geheimes_passwort</Password>
  <URL>https://example.com</URL>
  <Notes>Notizen</Notes>
</WalletRecord>
```

---

## 6. Zeitstempel-Format

Zeitstempel werden als Sekunden seit dem **01.01.2000 00:00:00 UTC** gespeichert:

```
timestamp = (DateTime.UtcNow.Ticks - 630822816000000000) / 10000000
```

**Beispiel:**

```
0x3142E6DE = 826.828.510 Sekunden
           = 01.01.2000 + 826.828.510s
           ≈ März 2026
```

---

## 7. Sicherheitsbewertung

### Stärken

- AES-256 Verschlüsselung
- Zwei-Schlüssel-System (PassKey/CipherKey)
- Key-Stretching (100.000 Iterationen, ~0,75s pro Versuch)
- Zufälliger Salt pro Datei

### Schwächen

- ECB-Modus (gleiche Klartextblöcke → gleiche Chiffretextblöcke)
- RIPEMD-160 statt SHA-256 für Key-Derivation
- Proprietäres Key-Stretching statt Standard-PBKDF2/bcrypt/scrypt
- XOR-Akkumulation als Key-Extension ist kryptographisch schwach
- Kein HMAC / authentifizierte Verschlüsselung (kein Manipulationsschutz)
- Bei `PassIterations=0`: nur ~91.000 Passwörter/Sekunde Brute-Force-Rate
- Statische Konstante fest im Code (kein zusätzliches Geheimnis)

---

## 8. Quellcode-Referenz

### DLLs (extrahiert aus Android APK, XALZ/LZ4-komprimiert)

| DLL | Größe | Inhalt |
|---|---|---|
| `Subsembly.SubFS.dll` | 37.888 Bytes | SubFileHeader, SubFile |
| `Subsembly.Crypto.dll` | 114.688 Bytes | CryAES, CryRipeMD160 |

### Relevante Methoden in SubFS.dll

| Methode | Funktion |
|---|---|
| `SubFileHeader._ComputePassHash()` | RIPEMD-160 + XOR-Akkumulation |
| `SubFileHeader._DerivePassKey()` | Key-Stretching mit AES |
| `SubFileHeader.VerifyPassword()` | Salt/SaltCrypt Vergleich |
| `SubFileHeader.InitPassword()` | Erstellt Salt/SaltCrypt/CipherKey |

### Relevante Methoden in Crypto.dll

| Methode | Funktion |
|---|---|
| `CryAES.Initialize()` | AES-Schlüssel setzen |
| `CryAES.CryptBlock()` | 16-Byte-Block ver-/entschlüsseln |
| `CryRipeMD160.HashCore/HashFinal()` | RIPEMD-160 Berechnung |

### Statische Konstanten (FieldRVA)

**PassHash-Salt (32 Bytes):**
```
903c4a1640b44381b199866aa4516d190cb0dcb8efa14c1a97ce043b341a34cf
```

**HeaderHash-Salt (16 Bytes, für interne Integritätsprüfung):**
```
80d61dca1dab48bdb86cf4be6f75008f
```

---

## 9. Entschlüsselungs-Tool

| | |
|---|---|
| Datei | `decrypt_wallet.py` |
| Sprache | Python 3 |
| Abhängigkeit | `pycryptodome` (`pip install pycryptodome`) |

**Verwendung:**

```bash
python3 decrypt_wallet.py <datei.wlt> <passwort>
```

**Ausgabe:**

- Ordnerstruktur
- Schema-Definitionen mit Feldtypen
- Datensätze (Passwörter, Benutzernamen, URLs etc.)

**Rückgabewert:** `0` = Erfolg, `1` = Fehler (falsches Passwort, ungültige Datei)
