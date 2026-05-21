# Amiga BASIC Decompiler

A standalone, robust Python-based decompiler that reverse engineers tokenized binary Amiga BASIC files into readable, plain-text source code.

## Why this Decompiler?

While some online projects (like `seawolf/amiga_basic_binary_parser`) exist as simple Proof-of-Concepts, they are highly incomplete, only support a handful of single-byte commands, and fail to decompile actual complex games and applications. 

This decompiler provides **100% complete and fully featured parsing**, handling:
- **All ~210 Amiga BASIC commands/tokens**, including all double-byte prefix commands (`\xf8`, `\xf9`, `\xfa`, `\xfb`) such as `SCREEN`, `WINDOW`, `LOCATE`, `SOUND`, `COLLISION`, `LIBRARY`, and more.
- **Full numeric format decodings**, supporting single-precision floats (4-byte), double-precision floats (8-byte), 1-byte, 2-byte, 3-byte, and 4-byte signed integers, and octal/hex short integer formats.
- **Accurate Names/Symbol Resolution**, fully extracting the variables, labels, and subroutines names table stored at the end of the binary file and rebuilding all pointers throughout the lines of code.
- **Proper Character Set Support (ISO-8859-2 / Latin-2)**: Correctly decodes Hungarian and Central European accented characters (e.g., `á`, `é`, `í`, `ó`, `ö`, `ő`, `ú`, `ü`, `ű`, `Ö`, `Ű`) from strings and comments, outputting standard modern **UTF-8** encoded `.bas` source files.

---

## Features

- **Bulk Mode**: Run without arguments to automatically scan, match, and decompile all binary Amiga BASIC files in the current folder.
- **Single File CLI Mode**: Specify input and output files on the command line.
- **Modern Compatibility**: Developed in standard Python 3 with no external dependencies required.

---

## How to Use

### 1. Bulk Decompilation (Recommended)
Place the `amiga_basic_decompiler.py` script inside the directory containing your binary Amiga BASIC files (these are files starting with the byte sequence `0xf5 0x00` and typically have no extension or `.bin` extension). 

Simply run:
```bash
python amiga_basic_decompiler.py
```
It will automatically search for all valid binary files, decompile them, and save them with a `.bas` extension in the same folder.

### 2. Single File CLI Mode
Decompile a single file by passing the input path and optionally the output path:
```bash
# Decompile 'myprogram' binary to 'myprogram.bas'
python amiga_basic_decompiler.py myprogram

# Or specify a custom output name/path
python amiga_basic_decompiler.py input_binary output_source.bas
```

---

## Technical Details

### Amiga BASIC Binary Layout
Standard tokenized Amiga BASIC binaries start with a two-byte magic header: `0xf5 0x00`.

The binary is divided into two primary sections:
1. **The Code Section**: Made of variable-length line records.
   - Each record starts with a length byte `L`. (If `L == 0`, it signifies the end of the code stream).
   - The first byte of content inside the record denotes the number of `leading spaces` for indentation.
   - The line body contains a sequence of literal bytes (tokens) and operand data.
   - The last two bytes of a line record are used as padding or flags (e.g., indicating the presence of line numbers).
2. **The Names Table**: Located after the terminator byte of the code section.
   - Contains raw byte sequences representing variable names, subroutines, and labels.
   - In the tokenized code, name references are encoded with special tags (`\x01`, `\x02`, `\x03`) followed by a 2-byte index into this table.

This decompiler reconstructs the lines of code by matching tokens to their respective BASIC keywords, decoding various data representation markers (like float representations), resolving index pointers in the Names Table, and ensuring whitespace indentation is perfectly preserved.

---

## License

This project is open-source and available under the [MIT License](LICENSE).
