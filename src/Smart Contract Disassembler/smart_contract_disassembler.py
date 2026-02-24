import re
from pathlib import Path

# EVM opcodes
OPCODES = {0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV",
           0x05: "SDIV", 0x06: "MOD", 0x07: "SMOD", 0x08: "ADDMOD", 0x09: "MULMOD",
           0x0A: "EXP", 0x0B: "SIGNEXTEND",
           0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT", 0x14: "EQ",
           0x15: "ISZERO", 0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT",
           0x1A: "BYTE", 0x1B: "SHL", 0x1C: "SHR", 0x1D: "SAR",
           0x20: "SHA3",
           0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN", 0x33: "CALLER",
           0x34: "CALLVALUE", 0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE",
           0x37: "CALLDATACOPY", 0x38: "CODESIZE", 0x39: "CODECOPY",
           0x3A: "GASPRICE", 0x3B: "EXTCODESIZE", 0x3C: "EXTCODECOPY",
           0x3D: "RETURNDATASIZE", 0x3E: "RETURNDATACOPY", 0x3F: "EXTCODEHASH",
           0x40: "BLOCKHASH", 0x41: "COINBASE", 0x42: "TIMESTAMP", 0x43: "NUMBER",
           0x44: "DIFFICULTY", 0x45: "GASLIMIT", 0x46: "CHAINID", 0x47: "SELFBALANCE",
           0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8",
           0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI",
           0x58: "PC", 0x59: "MSIZE", 0x5A: "GAS", 0x5B: "JUMPDEST",
           **{0x60 + i: f"PUSH{i+1}" for i in range(32)},
           **{0x80 + i: f"DUP{i+1}" for i in range(16)},
           **{0x90 + i: f"SWAP{i+1}" for i in range(16)},
           **{0xA0 + i: f"LOG{i}" for i in range(5)},
           0xF0: "CREATE", 0xF1: "CALL", 0xF2: "CALLCODE", 0xF3: "RETURN",
           0xF4: "DELEGATECALL", 0xF5: "CREATE2", 0xFA: "STATICCALL",
           0xFD: "REVERT", 0xFE: "INVALID", 0xFF: "SELFDESTRUCT"}

HEX_TEXT_RE = re.compile(r"^(0x)?[0-9a-fA-F\s]+$")

# Return a clean hex string representing the bytecode.
def read_hex_from_file(param_path: Path) -> str:
    raw = Path(param_path).read_bytes()

    # Try interpret as text hex
    try:
        txt = raw.decode("utf-8", errors="ignore").strip()
        if HEX_TEXT_RE.fullmatch(txt):
            txt = txt.strip()
            if txt.lower().startswith("0x"):
                txt = txt[2:]
            # remove whitespace only (spaces/newlines/tabs)
            txt = re.sub(r"\s+", "", txt)
            return txt.lower()
    except Exception:
        pass
    # Otherwise treat as raw bytecode
    return raw.hex()

# Convert hex string into assembly + token list.
def disassemble(hexstr: str, include_push_data_as_token: bool = False) -> tuple[list[str], list[str]]:
    if not hexstr:
        return [], []

    if len(hexstr) % 2 != 0:
        # odd-length hex -> trim final nibble
        hexstr = hexstr[:-1]

    try:
        data = bytes.fromhex(hexstr)
    except ValueError as e:
        raise ValueError(f"Invalid hex string (len={len(hexstr)}): {e}") from e

    i = 0
    asm_lines: list[str] = []
    tokens: list[str] = []

    while i < len(data):
        addr = i
        b = data[i]
        i += 1

        if 0x60 <= b <= 0x7f:
            n = b - 0x5f  # PUSH1 is 0x60 -> 1

            truncated = False
            if i + n > len(data):
                push_bytes = data[i:]
                i = len(data)
                truncated = True
            else:
                push_bytes = data[i:i + n]
                i += n

            mnemonic = f"PUSH{n}"
            imm = push_bytes.hex()

            token = f"{mnemonic}_0x{imm}" if include_push_data_as_token else mnemonic
            tokens.append(token)

            if truncated:
                asm_lines.append(f"{addr:04x}: {mnemonic} 0x{imm}  ; TRUNCATED ({len(push_bytes)}/{n})")
            else:
                asm_lines.append(f"{addr:04x}: {mnemonic} 0x{imm}")

        else:
            mnemonic = OPCODES.get(b, f"UNKNOWN_0x{b:02x}")
            asm_lines.append(f"{addr:04x}: {mnemonic}")
            tokens.append(mnemonic)

    return asm_lines, tokens

# Read bytecode
# Disassemble
# Save .asm file into either vulnerable/ or benign/
# Append token sequence into all_token_sequences
# Record mapping in file_token_map
def smartcontract_to_disassembler(all_token_sequences: list[list[str]],
                                  file_token_map: dict[Path, list[str]],
                                  param_file_path: Path, 
                                  param_label : bool,
                                  param_disasm_directory: Path,
                                  param_include_push_data_as_token : bool)  -> tuple[bool, Path] :
    try:
        hexstr = read_hex_from_file(param_file_path)
        if not hexstr:
            print(f"Skipping empty file: {param_file_path}")
            return False, param_file_path
        asm_lines, tokens = disassemble(hexstr, param_include_push_data_as_token)
        if param_label:
            out_dir = param_disasm_directory / "vulnerable"
        else:
            out_dir = param_disasm_directory / "benign"
        out_asm = Path(out_dir / f"{param_file_path.stem}.asm")
        print(f"smartcontract_to_disassembler: Output will:{out_asm}")
        out_asm.parent.mkdir(parents=True, exist_ok=True)
        
        out_asm.write_text("\n".join(asm_lines), encoding="utf-8")
        print(f"smartcontract_to_disassembler: Wrote ASM: {out_asm}")
        all_token_sequences.append(tokens) #[[]]
        #all_token_sequences.extend(tokens) #!..
        file_token_map[param_file_path] = tokens
        return True, param_file_path
    except Exception as e:
        print(f"smartcontract_to_disassembler: Error processing {param_file_path}: {e}")
        return False, param_file_path

def main() -> None:
    contract_file = Path("data/contracts/0x1234.bytecode")
    label = True  # True => vulnerable, False => benign
    out_dir = Path("output/disasm")  # output root directory
    include_push_data_as_token = False  # True if you want PUSH bytes included in token

    # --- required containers (these are outputs you pass in to be filled) ---
    all_token_sequences: list[list[str]] = []
    file_token_map: dict[Path, list[str]] = {}

    success, processed_path = smartcontract_to_disassembler(all_token_sequences=all_token_sequences,
                                                            file_token_map=file_token_map,
                                                            param_file_path=contract_file,
                                                            param_label=label,
                                                            param_disasm_directory=out_dir,
                                                            param_include_push_data_as_token=include_push_data_as_token)

    print("Success:", success)
    print("Processed file:", processed_path)

    if success:
        print("Token count:", len(file_token_map[processed_path]))
        print("First 20 tokens:", file_token_map[processed_path][:20])

        # The written asm file will be in:
        subfolder = "vulnerable" if label else "benign"
        asm_path = out_dir / subfolder / f"{processed_path.stem}.asm"
        print("ASM written to:", asm_path)

if __name__ == "__main__":
    main()