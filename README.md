# showeo - A c++ x64 dissasembler library

A clean, two-header library for x64 binary analysis with both disassembly and decompilation capabilities.

## Features

- **Full x64 instruction decoding** - Supports all common x64 instructions including prefixes, ModR/M, SIB, and displacements
- **Basic block analysis** - Automatic control flow graph construction
- **Loop detection** - Identifies while and do-while loops using SCC analysis
- **Stack frame analysis** - Reconstructs local variables and function parameters
- **C pseudocode generation** - Outputs readable C code from binary input
- **Lightweight** - Minimal dependencies, easy to integrate

## API Reference

### Disassembler (`x64disasm`)

```cpp
#include "x64disasm.h"

x64disasm dis;
dis.set_pseudo_c(true);                    // enable pseudocode generation
dis.set_base(0x1000);                      // set base address

// decode binary
auto insns = dis.decode(code, size, base_addr);

// find branch targets
auto targets = dis.find_branches(code, size, base_addr);

// generate pseudocode
std::string c_code = dis.to_pseudo_c(insns, "my_function");
```

### Decompiler (`x64decomp`)

```cpp
#include "x64decomp.h"

// convert disassembler output to decompiler format
x64decomp::insn_list_t list;
for (const auto& ins : insns)
    list.push_back({ins.addr, {ins.mnemonic, ins.operands}});

// decompile
x64decomp decomp(base_addr);
decomp.set_function_bounds(start, end);
std::string c_code = decomp.decompile(list);
```

## Data Structures

### `insn_t`
| Field | Description |
|-------|-------------|
| `addr` | Instruction address |
| `bytes` | Raw instruction bytes |
| `len` | Instruction length |
| `mnemonic` | Instruction name (mov, add, jmp, etc.) |
| `operands` | Instruction operands |
| `target` | Branch target address (if branch) |
| `is_branch` | True if branch instruction |
| `is_conditional` | True if conditional branch |
| `pseudo_c` | Generated pseudocode (optional) |

## Example

```cpp
uint8_t code[] = {
    0x55, 0x48, 0x89, 0xe5,           // push rbp; mov rbp, rsp
    0x89, 0x7d, 0xfc,                 // mov [rbp-4], edi
    0x8b, 0x45, 0xfc,                 // mov eax, [rbp-4]
    0x83, 0xc0, 0x01,                 // add eax, 1
    0x5d, 0xc3                        // pop rbp; ret
};

x64disasm dis;
auto insns = dis.decode(code, sizeof(code), 0x1000);
std::string code = dis.to_pseudo_c(insns, "increment");
```

**Output:**
```c
void increment() {
    /* push rbp */
    rbp = rsp;
    ebp = edi;
    eax = ebp;
    eax += 1;
    /* pop rbp */
    return;
}
```

## Limitations

- x64 only (no x86 support)
- No floating point or SIMD instructions
- Limited switch statement detection
- Basic type inference only

## License

MIT
