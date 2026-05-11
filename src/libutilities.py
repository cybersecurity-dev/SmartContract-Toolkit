
DEFAULT_EXTS = {".bin", ".bytecode", ".evm"}

def is_smart_contract_file(param_file_path: str) -> bool:
    return param_file_path.lower().endswith(tuple(DEFAULT_EXTS))
