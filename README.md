# API Hashing Finder Tool

## Description

This tool analyzes a PE file or shellcode to identify probable hash values used in API hashing mechanisms. The purpose is to detect hidden API calls that malware authors often use to obfuscate their import table.
The script disassembles the executable code, extracts potential API hash values, and identifies which functions resolve them. It provides different output modes to help analyze and interpret the results.

## Features

- Detects probable API hash values in a PE file or raw shellcode.
- Identifies resolving functions that might use these hashes.
- Offers different output modes:
  - **Default mode**: Outputs the most referenced hash list.
  - **All mode**: Displays all detected hash values.
  - **Verbose mode**: Provides detailed information, including hash addresses and resolving function addresses.
- Supports both 32-bit and 64-bit binaries.
- Can generate an output file containing the results. [Not implemented yet ;)]

## Requirements

- Python 3
- Required Python libraries:
  - `pefile`
  - `numpy`
  - `capstone`
  - `argparse`

You can install the dependencies using:
```bash
pip install -r requirements.txt
```

## Usage

```bash
python script.py -f <path_to_binary> [options]
```

### Arguments:

- `-f, --file <path>` : Specify the binary file to analyze (required).
- `-a, --all` : Show all lists of probable hash values (recommended for deeper analysis).
- `-o, --output <file>` : Save the results to a file.
- `-v, --verbose` : Display detailed information about hash values.

### Example:

```bash
python api_hashing_finder.py -f malv_file.bin -av
```
```txt
                [SNIPPED]

-> Hash value found in the binary
                [Max x-ref] -> 139 calls
                0xac136ba
                0x4ba8e6a6
                0xbecffe7a
                0x6a3b053f
                0x5bfec5c3
                0xd8a06af
                0x11fe0a3
                0xd4540229

                [SNIPPED]

-> Hash value found in the binary

        - Probable API-Resolve function at 0x10001620
                [Max x-ref] -> 139 calls

                Hash address -> 0x10001024
                Hash value   -> 0xac136ba

                Hash address -> 0x10001061
                Hash value   -> 0x4ba8e6a6

                Hash address -> 0x10001104
                Hash value   -> 0xbecffe7a

                [SNIPPED]
   
```

This will analyze `malv_file.bin`, displaying all detected hash values and detailed information.

## Output Interpretation

- The tool extracts hex values from `push` and `mov` instructions.
- It filters out values that are unlikely to be hashes (e.g., small constants, loop indices).
- It identifies the resolving functions by checking for `call` instructions within a short range.
- The most frequently used hash values and the most dispersed hash values (statistically) are highlighted.

## Limitations

- Some hash algorithms may use consecutive values, which could require tweaking the filtering conditions.
- The script does not attempt to brute-force or resolve the hash values back to API names.

## License

This project is released under the MIT License.

## Author

R3dy

