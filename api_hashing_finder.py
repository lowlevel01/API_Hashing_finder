import pefile
import numpy as np
from capstone import *
import re
import argparse
import time

def is_pe_file(file_path):
    try:
        with open(file_path, "rb") as file:
            return file.read(2) == b'MZ'
    except pefile.PEFormatError as e:
        print(f"Erreur de format PE : {e.value}")
        return False

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
        if b'\x48\x89' in code_section: 
            CS_MODE = CS_MODE_64
        code_base = 0x0

    md = Cs(CS_ARCH_X86, CS_MODE)
    disasm_list = list(md.disasm(code_section, code_base))
    
    #suspicious_hex_value = []
    no_suspicious_hex_address = []
    probable_resolve_function = []
    result = {}
    count_hash = {}
    count = 0

    for i, instr in enumerate(disasm_list):

        # For the moment, the script get hex value from -push- and -mov- instructions
        if instr.mnemonic in ["push", "mov"]:
            try:
                # In case of a -mov- mnemonic, we only get the second operands : mov eax, 0x????????
                operand = instr.op_str.split(',')[-1].strip() if instr.mnemonic == "mov" else instr.op_str.strip()
                if re.fullmatch(r'0x[0-9A-Fa-f]+', operand):  
                    op = int(operand, 16)
                    # What's a probable hash value in hexadecimal ?
                    # A value > 0x10000
                    # The number of '0' < 1 to avoid offset like 0x1230000 | Maybe increase at 2 (->3)
                    # The number of 'f' < 4 to avoid test value like 0xffffffff
                    # Avoid the maximum of occurences of consecutive value like 0x123...,0x123,....
                    # WARNING, some hash algorithms can use consecutive value, maybe edit the conditions...
                    # Skip small hex value to avoid constant or loop index
                    if (0x10000 < op and 
                    str(hex(op)).count('0') <= 2 and 
                    str(hex(op)).count('f') <= 4 and 
                    # op not in suspicious_hex_value and 
                    hex(op)[:6] not in no_suspicious_hex_address and 
                    op > 0xFFFFFF):
                        
                        no_suspicious_hex_address.append(hex(op)[:6])
                        #suspicious_hex_value.append(op)
                        
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
                                count+=1
                                break  
                        count_hash[next_instr.op_str] = count
                        #print(count_hash[next_instr.op_str])
            except ValueError as e:
                print(e)
                continue  

    #print(count_hash)
    max_address = max(count_hash, key=count_hash.get)
    max_count = count_hash[max_address]
    print(f"\nHave value of the most called list (x-ref)")
    for key, list_hash in result.items():
        if key == max_address:
            for entry in list_hash:
                print(entry['hash_value'])
    
    if(args.all == True):
        #print(count)
        # The most dispersed list
        best_std = float('-inf')
        best_list = None
        for key, list_hash in result.items():
            stat_test = [int(entry["hash_value"], 16) for entry in list_hash]
            stat_test.sort()
            diffs = np.diff(stat_test)
            
            if len(diffs) > 0:
                std_dev = np.std(diffs)
                #print(key, std_dev)
                if std_dev > best_std:  
                    best_std = std_dev
                    best_list = key  


        print("\n-> Hash value found in the binary")
        for key, list_hash in result.items():
            if(key == best_list):
                print("\n\t\t[More dispersed]")
            if(key == max_address):
                print(f"\t\t[Max x-ref] -> {max_count} calls")
            
            for entry in list_hash:
                print(f"\t\t{entry['hash_value']}")

                    
    if(args.verbose == True):
        # All the hash retrieved
        print("\n-> Hash value found in the binary")
        for key, list_hash in result.items():
            print(f"\n\t- Probable API-Resolve function at {key}")
            if(key == best_list):
                print("\n\t\t[More dispersed]")
            if(key == max_address):
                print(f"\t\t[Max x-ref] -> {max_count} calls")
            
            for entry in list_hash:
                print(f"\n\t\tHash address -> {hex(entry['address_of_hash'])}")
                print(f"\t\tHash value   -> {entry['hash_value']}")

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Parameters are -h, -f, -a/--all and -o.")

   
    parser.add_argument("-f", "--file", help="Binary file to analyze (PE-file or shellcode)", type=str, required=True)
    parser.add_argument("-a", "--all", help="This mode will show you all the list of probable hash value (Advised)\nDefault mode output the most called list (x-ref)", action="store_true")
    parser.add_argument("-o", "--output", help="Create a simple file with all the hash value according to your mod (default/all)", type=str)
    parser.add_argument('-v', "--verbose", help="Give you more informations about the hash values (Address of the resolving function, address of the value,...)", action="store_true")
    
    args = parser.parse_args()

    #print(f"Mode all activé : {args.all}")

    print(f"\nBeginning of the analysis : {args.file}")
    if args.output:
        print(f"\nOutput file : {args.output}")
    else:
        print("None output file given, output -> Terminal.")
    time.sleep(2)
    exe_path = args.file
    try:
        api_hashing_indicator(exe_path, is_pe_file(exe_path))
    except OSError as e:
        print(f"Erreur d'accès au fichier : {e}")
   
