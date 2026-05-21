#!/usr/bin/env python3
"""
Amiga BASIC Decompiler
Reverse engineers tokenized binary Amiga BASIC files to readable source code.
"""

import os
import sys
import struct

# Table of Amiga BASIC commands/tokens extracted from reverse-engineered specifications
COMMANDS = {
    (0x80, 0x00): "ABS",
    (0x81, 0x00): "ASC",
    (0x82, 0x00): "ATN",
    (0x83, 0x00): "CALL",
    (0x84, 0x00): "CDBL",
    (0x85, 0x00): "CHR$",
    (0x86, 0x00): "CINT",
    (0x87, 0x00): "CLOSE",
    (0x88, 0x00): "COMMON",
    (0x89, 0x00): "COS",
    (0x8a, 0x00): "CVD",
    (0x8b, 0x00): "CVI",
    (0x8c, 0x00): "CVS",
    (0x8d, 0x00): "DATA",
    (0x8e, 0x00): "ELSE",
    (0x8f, 0x00): "EOF",
    (0x90, 0x00): "EXP",
    (0x91, 0x00): "FIELD",
    (0x92, 0x00): "FIX",
    (0x93, 0x00): "FN",
    (0x94, 0x00): "FOR",
    (0x95, 0x00): "GET",
    (0x96, 0x00): "GOSUB",
    (0x97, 0x00): "GOTO",
    (0x98, 0x00): "IF",
    (0x99, 0x00): "INKEY$",
    (0x9a, 0x00): "INPUT",
    (0x9b, 0x00): "INT",
    (0x9c, 0x00): "LEFT$",
    (0x9d, 0x00): "LEN",
    (0x9e, 0x00): "LET",
    (0x9f, 0x00): "LINE",
    (0xa1, 0x00): "LOC",
    (0xa2, 0x00): "LOF",
    (0xa3, 0x00): "LOG",
    (0xa4, 0x00): "LSET",
    (0xa5, 0x00): "MID$",
    (0xa6, 0x00): "MKD$",
    (0xa7, 0x00): "MKI$",
    (0xa8, 0x00): "MKS$",
    (0xa9, 0x00): "NEXT",
    (0xaa, 0x00): "ON",
    (0xab, 0x00): "OPEN",
    (0xac, 0x00): "PRINT",
    (0xad, 0x00): "PUT",
    (0xae, 0x00): "READ",
    (0xaf, 0x00): "REM",
    (0xaf, 0xe8): "'",
    (0xb0, 0x00): "RETURN",
    (0xb1, 0x00): "RIGHT$",
    (0xb2, 0x00): "RND",
    (0xb3, 0x00): "RSET",
    (0xb4, 0x00): "SGN",
    (0xb5, 0x00): "SIN",
    (0xb6, 0x00): "SPACE$",
    (0xb7, 0x00): "SQR",
    (0xb8, 0x00): "STR$",
    (0xb9, 0x00): "STRING$",
    (0xba, 0x00): "TAN",
    (0xbc, 0x00): "VAL",
    (0xbd, 0x00): "WEND",
    (0xbe, 0xec): "WHILE",
    (0xbf, 0x00): "WRITE",
    (0xc0, 0x00): "ELSEIF",
    (0xc1, 0x00): "CLNG",
    (0xc2, 0x00): "CVL",
    (0xc3, 0x00): "MKL$",
    (0xc4, 0x00): "AREA",
    (0xe3, 0x00): "STATIC",
    (0xe4, 0x00): "USING",
    (0xe5, 0x00): "TO",
    (0xe6, 0x00): "THEN",
    (0xe7, 0x00): "NOT",
    (0xe9, 0x00): ">",
    (0xea, 0x00): "=",
    (0xeb, 0x00): "<",
    (0xec, 0x00): "+",
    (0xed, 0x00): "-",
    (0xee, 0x00): "*",
    (0xef, 0x00): "/",
    (0xf0, 0x00): "^",
    (0xf1, 0x00): "AND",
    (0xf2, 0x00): "OR",
    (0xf3, 0x00): "XOR",
    (0xf4, 0x00): "EQV",
    (0xf5, 0x00): "IMP",
    (0xf6, 0x00): "MOD",
    (0xf7, 0x00): "\\\\",
    (0xf8, 0x81): "CHAIN",
    (0xf8, 0x82): "CLEAR",
    (0xf8, 0x83): "CLS",
    (0xf8, 0x84): "CONT",
    (0xf8, 0x85): "CSNG",
    (0xf8, 0x86): "DATE$",
    (0xf8, 0x87): "DEFINT",
    (0xf8, 0x88): "DEFSNG",
    (0xf8, 0x89): "DEFDBL",
    (0xf8, 0x8a): "DEFSTR",
    (0xf8, 0x8b): "DEF",
    (0xf8, 0x8c): "DELETE",
    (0xf8, 0x8d): "DIM",
    (0xf8, 0x8f): "END",
    (0xf8, 0x90): "ERASE",
    (0xf8, 0x91): "ERL",
    (0xf8, 0x92): "ERROR",
    (0xf8, 0x93): "ERR",
    (0xf8, 0x94): "FILES",
    (0xf8, 0x95): "FRE",
    (0xf8, 0x96): "HEX$",
    (0xf8, 0x97): "INSTR",
    (0xf8, 0x98): "KILL",
    (0xf8, 0x9a): "LLIST",
    (0xf8, 0x9b): "LOAD",
    (0xf8, 0x9c): "LPOS",
    (0xf8, 0x9d): "LPRINT",
    (0xf8, 0x9e): "MERGE",
    (0xf8, 0x9f): "NAME",
    (0xf8, 0xa0): "NEW",
    (0xf8, 0xa1): "OCT$",
    (0xf8, 0xa2): "OPTION",
    (0xf8, 0xa3): "PEEK",
    (0xf8, 0xa4): "POKE",
    (0xf8, 0xa5): "POS",
    (0xf8, 0xa6): "RANDOMIZE",
    (0xf8, 0xa8): "RESTORE",
    (0xf8, 0xa9): "RESUME",
    (0xf8, 0xaa): "RUN",
    (0xf8, 0xab): "SAVE",
    (0xf8, 0xad): "STOP",
    (0xf8, 0xae): "SWAP",
    (0xf8, 0xaf): "SYSTEM",
    (0xf8, 0xb0): "TIME$",
    (0xf8, 0xb1): "TRON",
    (0xf8, 0xb2): "TROFF",
    (0xf8, 0xb3): "VARPTR",
    (0xf8, 0xb4): "WIDTH",
    (0xf8, 0xb5): "BEEP",
    (0xf8, 0xb6): "CIRCLE",
    (0xf8, 0xb8): "MOUSE",
    (0xf8, 0xb9): "POINT",
    (0xf8, 0xba): "PRESET",
    (0xf8, 0xbb): "PSET",
    (0xf8, 0xbc): "RESET",
    (0xf8, 0xbd): "TIMER",
    (0xf8, 0xbe): "SUB",
    (0xf8, 0xbf): "EXIT",
    (0xf8, 0xc0): "SOUND",
    (0xf8, 0xc2): "MENU",
    (0xf8, 0xc3): "WINDOW",
    (0xf8, 0xc5): "LOCATE",
    (0xf8, 0xc6): "CSRLIN",
    (0xf8, 0xc7): "LBOUND",
    (0xf8, 0xc8): "UBOUND",
    (0xf8, 0xc9): "SHARED",
    (0xf8, 0xca): "UCASE$",
    (0xf8, 0xcb): "SCROLL",
    (0xf8, 0xcc): "LIBRARY",
    (0xf8, 0xd2): "PAINT",
    (0xf8, 0xd3): "SCREEN",
    (0xf8, 0xd4): "DECLARE",
    (0xf8, 0xd5): "FUNCTION",
    (0xf8, 0xd6): "DEFLNG",
    (0xf8, 0xd7): "SADD",
    (0xf8, 0xd8): "AREAFILL",
    (0xf8, 0xd9): "COLOR",
    (0xf8, 0xda): "PATTERN",
    (0xf8, 0xdb): "PALETTE",
    (0xf8, 0xdc): "SLEEP",
    (0xf8, 0xdd): "CHDIR",
    (0xf8, 0xde): "STRIG",
    (0xf8, 0xdf): "STICK",
    (0xf9, 0xf4): "OFF",
    (0xf9, 0xf5): "BREAK",
    (0xf9, 0xf6): "WAIT",
    (0xf9, 0xf8): "TAB",
    (0xf9, 0xf9): "STEP",
    (0xf9, 0xfa): "SPC",
    (0xf9, 0xfb): "OUTPUT",
    (0xf9, 0xfc): "BASE",
    (0xf9, 0xfd): "AS",
    (0xf9, 0xfe): "APPEND",
    (0xf9, 0xff): "ALL",
    (0xfa, 0x80): "WAVE",
    (0xfa, 0x81): "POKEW",
    (0xfa, 0x82): "POKEL",
    (0xfa, 0x83): "PEEKW",
    (0xfa, 0x84): "PEEKL",
    (0xfa, 0x85): "SAY",
    (0xfa, 0x86): "TRANSLATE$",
    (0xfa, 0x87): "OBJECT.SHAPE",
    (0xfa, 0x88): "OBJECT.PRIORITY",
    (0xfa, 0x89): "OBJECT.X",
    (0xfa, 0x8a): "OBJECT.Y",
    (0xfa, 0x8b): "OBJECT.VX",
    (0xfa, 0x8c): "OBJECT.VY",
    (0xfa, 0x8d): "OBJECT.AX",
    (0xfa, 0x8e): "OBJECT.AY",
    (0xfa, 0x8f): "OBJECT.CLIP",
    (0xfa, 0x90): "OBJECT.PLANES",
    (0xfa, 0x91): "OBJECT.HIT",
    (0xfa, 0x92): "OBJECT.ON",
    (0xfa, 0x93): "OBJECT.OFF",
    (0xfa, 0x94): "OBJECT.START",
    (0xfa, 0x95): "OBJECT.STOP",
    (0xfa, 0x96): "OBJECT.CLOSE",
    (0xfa, 0x97): "COLLISION",
    (0xfb, 0xff): "PTAB",
}

def raw_to_amiga_basic(data):
    """
    Parses a raw Amiga BASIC binary file into lines of code and names table.
    """
    if len(data) < 2 or data[0:2] != b'\xf5\x00':
        raise ValueError("Invalid Amiga BASIC file header. Expected 0xf5 0x00.")
        
    cursor = 2
    lines = []
    codelines = True
    names = []
    
    while cursor < len(data):
        prev = cursor
        L = data[cursor]
        cursor = cursor + L
        
        if cursor == prev:
            # Terminator reached, stop line parsing
            codelines = False
            cursor += 1
            if cursor < len(data) and data[cursor] == 0:
                cursor += 1
            if cursor < len(data) and cursor % 2 == 0:
                cursor += 1
        else:
            if codelines:
                # Code line
                r = data[prev+1:cursor]
                lines.append(r)
            else:
                # Name table item
                r = data[prev+1:cursor+1]
                names.append(r.decode('iso-8859-2', errors='replace'))
                cursor += 1
                
    return lines, names

def format_single(num):
    """
    Formats a 4-byte single-precision float using Amiga BASIC rules.
    """
    s = f"{num:.7g}".upper()
    if "E" not in s:
        s = s.replace("0.", ".")
        s = s.replace("-0.", "-.")
    if "." not in s and "E" not in s:
        s += "!"
    return s

def format_double(num):
    """
    Formats an 8-byte double-precision float using Amiga BASIC rules.
    """
    s = f"{num:.16g}".upper()
    if "E" not in s:
        s = s.replace("0.", ".")
        s = s.replace("-0.", "-.")
    s = s.replace("E", "D")
    if "D" not in s:
        s += "#"
    return s

def decompile_line(line, names):
    """
    Decompiles a single tokenized raw line of code using the names table.
    """
    if len(line) == 0:
        return ""
        
    leading_spaces = line[0]
    cmdln = " " * leading_spaces
    ln = line[1:]
    
    # Check if there is a numeric label at the beginning
    if len(ln) > 2:
        has_label = False
        # If the last byte of the padding has 0x80 set, it's a numeric label
        if (line[-1] & 0x80) != 0:
            has_label = True
        else:
            # Fallback: check if the first token is NOT a valid command or a name reference
            ln1 = ln[0]
            ln2 = ln[1]
            is_valid_cmd = (ln1, ln2) in COMMANDS or (ln1, 0x00) in COMMANDS
            is_name_ref = ln1 in [1, 2, 3]
            if not (is_valid_cmd or is_name_ref):
                has_label = True
                
        if has_label:
            label_val = (ln[0] << 8) | ln[1]
            cmdln += str(label_val)
            ln = ln[2:]
            if len(ln) > 2:
                cmdln += " "
                
    while len(ln) > 2:  # Stop before last 2 bytes which are padding
        # Try to match 2-byte command
        matched_cmd = None
        consumed = 0
        
        if len(ln) > 3 and (ln[0], ln[1]) in COMMANDS:
            matched_cmd = COMMANDS[(ln[0], ln[1])]
            consumed = 2
        elif (ln[0], 0x00) in COMMANDS:
            matched_cmd = COMMANDS[(ln[0], 0x00)]
            consumed = 1
            
        if matched_cmd is not None:
            # Clean up preceding colons for control flow elements
            if matched_cmd in ["ELSE", "REM", "'"]:
                if cmdln.endswith(":"):
                    cmdln = cmdln[:-1]
                if matched_cmd in ["REM", "'"]:
                    # All remaining bytes of ln (excluding 2 bytes padding) are string comments
                    comment_bytes = ln[consumed:-2]
                    # Stop at the first null character if there is one
                    null_idx = comment_bytes.find(b'\x00')
                    if null_idx != -1:
                        comment_bytes = comment_bytes[:null_idx]
                    comment_text = comment_bytes.decode('iso-8859-2', errors='replace')
                    cmdln += matched_cmd + comment_text
                    break  # Break out of loop as REM consumes the rest of the line
                    
            cmdln += matched_cmd
            ln = ln[consumed:]
        elif ln[0] in [1, 2, 3]:
            # Name reference
            cd = ln[0]
            if cd == 3:
                ln = ln[1:]  # Consume extra null padding byte for label references
            idx = (ln[1] << 8) | ln[2]
            if idx < len(names):
                name = names[idx]
            else:
                name = f"<UNKNOWN_NAME_{idx}>"
            cmdln += name
            ln = ln[3:]
        elif ln[0] == 0x08:
            # Redundant code block following THEN or ELSEIF
            ln = ln[3:]
        elif 0x11 <= ln[0] <= 0x1a:
            # Single digit constants (0-9)
            cmdln += str(ln[0] - 0x11)
            ln = ln[1:]
        elif ln[0] == 0x0b:
            # Octal number representation
            val = (ln[1] << 8) | ln[2]
            cmdln += f"&O{val:o}"
            ln = ln[3:]
        elif ln[0] == 0x0c:
            # Hexadecimal short integer representation
            val = (ln[1] << 8) | ln[2]
            cmdln += f"&H{val:X}"
            ln = ln[3:]
        elif ln[0] == 0x0e:
            # 3-byte unsigned integer (sometimes numeric label references)
            val = (ln[1] << 16) | (ln[2] << 8) | ln[3]
            cmdln += str(val)
            ln = ln[4:]
        elif ln[0] == 0x0f:
            # 1-byte integer
            cmdln += str(ln[1])
            ln = ln[2:]
        elif ln[0] == 0x1c:
            # 2-byte signed integer
            val = (ln[1] << 8) | ln[2]
            if val >= 0x8000:
                val -= 0x10000
            cmdln += str(val)
            ln = ln[3:]
        elif ln[0] == 0x1d:
            # 4-byte single-precision float
            num = struct.unpack('>f', ln[1:5])[0]
            cmdln += format_single(num)
            ln = ln[5:]
        elif ln[0] == 0x1e:
            # 4-byte signed long integer
            val = (ln[1] << 24) | (ln[2] << 16) | (ln[3] << 8) | ln[4]
            if val >= 0x80000000:
                val -= 0x100000000
            cmdln += f"{val}&"
            ln = ln[5:]
        elif ln[0] == 0x1f:
            # 8-byte double-precision float
            num = struct.unpack('>d', ln[1:9])[0]
            cmdln += format_double(num)
            ln = ln[9:]
        elif ln[0] == 0x22:
            # Double quote string literal
            idx = 1
            while idx < len(ln) and ln[idx] != 0x22:
                if ln[idx] == 0x00:
                    break
                idx += 1
            str_bytes = ln[:idx+1]
            # Strip null characters in string
            str_bytes = bytearray([b for b in str_bytes if b != 0x00])
            cmdln += str_bytes.decode('iso-8859-2', errors='replace')
            ln = ln[idx+1:]
        else:
            # Fallback to direct ASCII character representation
            try:
                cmdln += bytes([ln[0]]).decode('iso-8859-2', errors='replace')
            except:
                pass
            ln = ln[1:]
            
    return cmdln

def decompile_file(input_path):
    """
    Reads an Amiga BASIC binary file and decompiles it into readable source code.
    """
    with open(input_path, 'rb') as f:
        data = f.read()
    
    lines, names = raw_to_amiga_basic(data)
    decompiled_lines = []
    
    for line in lines:
        decompiled_lines.append(decompile_line(line, names))
        
    return "\n".join(decompiled_lines)

def bulk_decompile(directory):
    """
    Finds all potential Amiga BASIC binary files in a directory and decompiles them.
    """
    files_processed = 0
    for f in os.listdir(directory):
        input_path = os.path.join(directory, f)
        if os.path.isdir(input_path):
            continue
            
        # Skip files that already have an extension or are the decompiler itself
        if '.' in f or f == 'amiga_basic_decompiler':
            continue
            
        try:
            # Check the signature first
            with open(input_path, 'rb') as file_obj:
                header = file_obj.read(2)
            if header == b'\xf5\x00':
                output_path = input_path + '.bas'
                print(f"Decompiling: {f} -> {f}.bas... ", end="", flush=True)
                decompiled_text = decompile_file(input_path)
                with open(output_path, 'w', encoding='utf-8') as out_f:
                    out_f.write(decompiled_text + "\n")
                print("SUCCESS!")
                files_processed += 1
        except Exception as e:
            print(f"Error while decompiling {f}: {e}")
            
    print(f"\nSuccessfully decompiled {files_processed} files.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # CLI Mode
        input_file = sys.argv[1]
        if len(sys.argv) > 2:
            output_file = sys.argv[2]
        else:
            output_file = input_file + '.bas'
            
        if not os.path.exists(input_file):
            print(f"Error: Input file does not exist: {input_file}")
            sys.exit(1)
            
        try:
            code = decompile_file(input_file)
            with open(output_file, 'w', encoding='utf-8') as out:
                out.write(code + "\n")
            print(f"Successfully decompiled: {input_file} -> {output_file}")
        except Exception as e:
            print(f"Error during decompilation: {e}")
            sys.exit(1)
    else:
        # Bulk Mode
        current_dir = os.path.dirname(os.path.realpath(__file__))
        print(f"Starting bulk decompilation in directory: {current_dir}\n")
        bulk_decompile(current_dir)
