import pefile
import numpy as np
from capstone import *
import re

def api_hashing_indicator(exe_path, is_pe_file):
    if is_pe_file:
        pe = pefile.PE(exe_path, fast_load=True)
        pe.parse_data_directories()
        code_section = None
        for section in pe.sections:
            if b".text" in section.Name:
                code_section = section.get_data()
                code_base = section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
                break
        if not code_section:
            print("No .text section found!")
            return  

        CS_MODE = CS_MODE_32 if hex(pe.FILE_HEADER.Machine) == hex(0x14c) else CS_MODE_64
    else:
        with open(exe_path, "rb") as f:
            code_section = f.read()
        CS_MODE = CS_MODE_32
        code_base = 0x0

    md = Cs(CS_ARCH_X86, CS_MODE)
    suspicious_hex_value = []
    no_suspicious_hex_address = []
    disasm_list = list(md.disasm(code_section, code_base))

    probable_resolve_function = []
    result = {}

    for i, instr in enumerate(disasm_list):
        if instr.mnemonic in ["push", "mov"]:
            try:
                operand = instr.op_str.split(',')[-1].strip() if instr.mnemonic == "mov" else instr.op_str.strip()
                if re.fullmatch(r'0x[0-9A-Fa-f]+', operand):  
                    op = int(operand, 16)
                    if (0x10000 < op and 
                    str(hex(op)).count('0') <= 2 and 
                    str(hex(op)).count('f') <= 4 and 
                    op not in suspicious_hex_value and 
                    hex(op)[:6] not in no_suspicious_hex_address and 
                    op > 0xFFFFFF):
                        
                        no_suspicious_hex_address.append(hex(op)[:6])
                        suspicious_hex_value.append(op)
                        for j in range(i + 1, min(i + 11, len(disasm_list))):  
                            next_instr = disasm_list[j]
                            if next_instr.mnemonic == "call":
                                probable_resolve_function.append(next_instr.op_str)
                                #print(next_instr.op_str)
                                if next_instr.op_str not in result:
                                    result[next_instr.op_str] = []
                                result[next_instr.op_str].append({
                                    'address_of_hash': instr.address,
                                    'hash_value': hex(op)
                                })
                                break  
            except ValueError as e:
                print(e)
                continue  

   
    best_std = float('-inf')
    best_list = None
    for key, list_hash in result.items():
        print(key)
        hash_values = [int(entry["hash_value"], 16) for entry in list_hash]
        hash_values.sort()
        print(hash_values)
    for key, list_hash in result.items():
        stat_test = [int(entry["hash_value"], 16) for entry in list_hash]
        stat_test.sort()
        diffs = np.diff(stat_test)
        
        if len(diffs) > 0:
            std_dev = np.std(diffs)
            print(key, std_dev)
            if std_dev > best_std:  
                best_std = std_dev
                best_list = key  



    if best_std != float('-inf'):
        print(f"\n La liste la plus dispersée est : {best_list} (Écart-type : {best_std})")
    else:
        print("\n Impossible de déterminer une liste logique.")
    count={}
    for key, list_hash in result.items():
        
        count[key] = len(list_hash)
        for entry in list_hash:
            print(key, entry['hash_value'])
    print(count)

def is_pe_file(file_path):
    try:
        with open(file_path, "rb") as file:
            return file.read(2) == b'MZ'
    except pefile.PEFormatError as e:
        print(f"Erreur de format PE : {e.value}")
        return False

if __name__ == "__main__":
    exe_path = "C:\\Users\\flarevm\\Desktop\\5f56d5748940e4039053f85978074bde16d64bd5ba97f6f0026ba8172cb29e93.exe"
    try:
        api_hashing_indicator(exe_path, is_pe_file(exe_path))
    except OSError as e:
        print(f"Erreur d'accès au fichier : {e}")
    except pefile.PEFormatError as e:
        print(f"Erreur de format PE : {e.value}")
