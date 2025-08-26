# CTF-Solver-Only-Reverse-Engineering

**Description:**  
CTF Advanced Analyzer is a Python-based tool for reverse engineering and CTF forensics. It detects PE/ELF formats, extracts ASCII/UTF-16 strings, finds flags via layered decoding (Base64/58/85, ROT, XOR, Vigenère), and reports APIs, DLLs, packers, entropy, and network usage. Generates detailed text reports.

---

## ✨ Features
- Detects binary format (PE/ELF), architecture, entry point, and sections.
- Extracts ASCII/UTF-16LE strings with offsets into `*.strings.txt`.
- Detects known flag formats: `picoCTF{}`, `TJCTF{}`, `DUCTF{}`, `lactf{}`, `actf{}`, `dice{}`, `uiuctf{}`.
- Multi-layer decoding: Base58/64/85/32/16, Atbash, Caesar, XOR, short-key Vigenère, compression (zlib/gzip/bz2/lzma).
- Recognises embedded encodings inside longer strings and decodes recursively.
- Identifies imported DLLs, crypto APIs, network APIs and URLs/domains.
- Computes entropy to detect packed/encrypted sections.
- Detects packers like UPX, MPRESS, FSG, Themida, VMProtect.
- Generates four reports:
  - `file.strings.txt` – all strings with offsets
  - `file.info.txt` – format, arch, sections, entropy, APIs, DLLs, packers
  - `file.functions.txt` – ELF function symbols
  - `file.flags.txt` – confirmed + possible flags

---

## ⚙️ Installation
No external dependencies. Requires Python 3.7+.

```bash
git clone https://github.com/sami-tor/CTF-Solver-Only-Reverse-Engineering
cd CTF-Solver-Only-Reverse-Engineering
python3 ctf_advanced_analyzer.py /path/to/binary

==== Analyzing main ====
File format: ELF
Architecture: 64-bit
Entry point: 0x10e0
File entropy: 1.76 bits/byte
Possible flag: picoCTF{numbers} (via decimal)

Generated files:
main.strings.txt
main.info.txt
main.functions.txt
main.flags.txt

🔧 Extending

You are free to modify and extend this tool:
Add new encoders/decoders (e.g. Base91).
Improve cipher detection (RC4, TEA/XTEA).
Enhance regex heuristics for flags.
Plug in ML models to classify strings.

```
📜 License

MIT License – free to use, modify, and distribute for personal, educational, or commercial use.


📚 References

Index of Coincidence – cryptanalysis basics:
Wikipedia – Index of Coincidence
Entropy & packer detection:
Medium – Understanding Packers for Malware
picoCTF flag format:
picoCTF Docs
TJCTF flag format:
TJCTF Writeup (Qiita)
DownUnderCTF flag format:
DUCTF Rules
General CTF flag patterns:
CTF 101

