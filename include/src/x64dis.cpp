/*
* Created by meltedcubes on 5/11/26, the c++ header for "x64decomp.h", apart of showeo library, licensed under MIT
 */
#include "../library/x64dis.hpp"
#include <sstream>
#include <iomanip>
#include <cstring>

x64disasm::x64disasm() {}

std::vector<insn_t> x64disasm::decode(const uint8_t* data, size_t size, uint64_t base_addr) {
    std::vector<insn_t> result;
    size_t off = 0;
    while (off < size) {
        insn_t ins = decode_one(data + off, size - off, base_addr + off);
        if (ins.len == 0) break;
        result.push_back(ins);
        off += ins.len;
    }
    return result;
}

insn_t x64disasm::decode_one(const uint8_t* code, size_t max_len, uint64_t addr) {
    insn_t ins = {};
    ins.addr = addr;
    if (max_len < 1) { ins.len = 1; return ins; }

    // parse prefixes
    bool rex = false, rex_w = false, rex_r = false, rex_x = false, rex_b = false;
    bool op66 = false, op67 = false;
    size_t pos = 0;

    while (pos < max_len) {
        uint8_t b = code[pos];
        if (b >= 0x40 && b <= 0x4f) {
            rex = true;
            rex_w = (b >> 3) & 1;
            rex_r = (b >> 2) & 1;
            rex_x = (b >> 1) & 1;
            rex_b = b & 1;
            pos++;
            continue;
        }
        if (b == 0x66) { op66 = true; pos++; continue; }
        if (b == 0x67) { op67 = true; pos++; continue; }
        break;
    }

    if (pos >= max_len) { ins.len = pos; return ins; }

    uint8_t op = code[pos++];
    uint64_t imm64 = 0;
    int64_t imm32 = 0, imm8 = 0, disp = 0;
    bool has_imm = false, has_disp = false;
    bool is_2byte = (op == 0x0f);
    uint8_t op2 = 0;

    if (is_2byte) {
        if (pos >= max_len) { ins.len = pos; return ins; }
        op2 = code[pos++];
    }

    // parse modrm
    uint8_t mod = 0, reg = 0, rm = 0;
    bool has_modrm = false;
    bool no_modrm = (op == 0xc3 || op == 0xcb || op == 0xc2 || op == 0xca || op == 0xcc || op == 0xcd ||
                     (op >= 0x70 && op <= 0x7f) || op == 0xeb || op == 0xe9 || op == 0xe8 ||
                     op == 0x90 || op == 0x9c || op == 0x9d || op == 0xfc || op == 0xfd ||
                     (op >= 0x50 && op <= 0x5f) || (op >= 0xb0 && op <= 0xbf) || op == 0x0f);

    if (!no_modrm && pos < max_len) {
        uint8_t modrm = code[pos++];
        mod = (modrm >> 6) & 3;
        reg = (modrm >> 3) & 7;
        rm = modrm & 7;
        has_modrm = true;

        if (rm == 4 && mod != 3 && pos < max_len) pos++; // sib
        if (mod == 1 && pos < max_len) { disp = (int8_t)code[pos]; pos++; has_disp = true; }
        else if (mod == 2 && pos + 4 <= max_len) { disp = *(int32_t*)(code + pos); pos += 4; has_disp = true; }
        else if (mod == 0 && rm == 5 && pos + 4 <= max_len) { disp = *(int32_t*)(code + pos); pos += 4; has_disp = true; }
    }

    // parse immediate
    if (pos < max_len) {
        if (op == 0xcd || op == 0xeb || (op >= 0x70 && op <= 0x7f) || op == 0x6a || op == 0xc0 || op == 0xc1) {
            imm8 = (int8_t)code[pos]; pos++; has_imm = true;
        } else if (op == 0xe8 || op == 0xe9) {
            imm32 = *(int32_t*)(code + pos); pos += 4; has_imm = true;
        } else if ((op == 0x05 || op == 0x0d || op == 0x15 || op == 0x1d || op == 0x25 ||
                    op == 0x2d || op == 0x35 || op == 0x3d) && !has_modrm) {
            imm32 = *(int32_t*)(code + pos); pos += 4; has_imm = true;
        } else if (op == 0x68 || op == 0xc7) {
            imm32 = *(int32_t*)(code + pos); pos += 4; has_imm = true;
        } else if (op == 0x83) {
            imm8 = (int8_t)code[pos]; pos++; has_imm = true;
        } else if (op >= 0xb0 && op <= 0xbf && pos + 4 <= max_len) {
            imm32 = *(int32_t*)(code + pos); pos += 4; has_imm = true;
        }
    }

    ins.len = pos;
    memcpy(ins.bytes, code, ins.len);

    // get register name helper
    auto reg_name = [&](uint8_t idx, bool ext) -> std::string {
        if (rex_w) {
            static const char* r64[] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                                        "r8","r9","r10","r11","r12","r13","r14","r15"};
            return r64[idx | (ext ? 8 : 0)];
        }
        if (op66) {
            static const char* r16[] = {"ax","cx","dx","bx","sp","bp","si","di",
                                        "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"};
            return r16[idx | (ext ? 8 : 0)];
        }
        static const char* r32[] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi",
                                    "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"};
        return r32[idx | (ext ? 8 : 0)];
    };

    // decode mnemonic and operands
    if (!is_2byte) {
        switch (op) {
            case 0x50 ... 0x57: ins.mnemonic = "push"; ins.operands = reg_name(op - 0x50, rex_b); break;
            case 0x58 ... 0x5f: ins.mnemonic = "pop"; ins.operands = reg_name(op - 0x58, rex_b); break;
            case 0x68: ins.mnemonic = "push"; ins.operands = to_hex(imm32); break;
            case 0x6a: ins.mnemonic = "push"; ins.operands = std::to_string(imm8); break;
            case 0x70 ... 0x7f: {
                const char* cond[] = {"jo","jno","jb","jnb","jz","jnz","jbe","ja",
                                      "js","jns","jp","jnp","jl","jnl","jle","jnle"};
                ins.mnemonic = cond[op - 0x70];
                ins.is_branch = true;
                ins.is_conditional = true;
                ins.target = addr + ins.len + imm8;
                ins.operands = to_hex(ins.target);
                break;
            }
            case 0x89: ins.mnemonic = "mov"; ins.operands = reg_name(rm, rex_b) + ", " + reg_name(reg, rex_r); break;
            case 0x8b: ins.mnemonic = "mov"; ins.operands = reg_name(reg, rex_r) + ", " + reg_name(rm, rex_b); break;
            case 0x8d:
                ins.mnemonic = "lea";
                ins.operands = reg_name(reg, rex_r) + ", " +
                               format_mem(mod, rm, rex_b, rex_w, op66, disp, has_disp);
                break;
            case 0x31: ins.mnemonic = "xor"; ins.operands = reg_name(rm, rex_b) + ", " + reg_name(reg, rex_r); break;
            case 0x33: ins.mnemonic = "xor"; ins.operands = reg_name(reg, rex_r) + ", " + reg_name(rm, rex_b); break;
            case 0x39: ins.mnemonic = "cmp"; ins.operands = reg_name(rm, rex_b) + ", " + reg_name(reg, rex_r); break;
            case 0x3b: ins.mnemonic = "cmp"; ins.operands = reg_name(reg, rex_r) + ", " + reg_name(rm, rex_b); break;
            case 0x81:
            case 0x83: {
                const char* alu[] = {"add","or","adc","sbb","and","sub","xor","cmp"};
                ins.mnemonic = alu[reg & 7];
                ins.operands = reg_name(rm, rex_b) + ", " + (op == 0x81 ? std::to_string(imm32) : std::to_string(imm8));
                break;
            }
            case 0xc3: ins.mnemonic = "ret"; ins.is_branch = true; break;
            case 0xc7: ins.mnemonic = "mov"; ins.operands = reg_name(rm, rex_b) + ", " + std::to_string(imm32); break;
            case 0xe8: ins.mnemonic = "call"; ins.is_branch = true; ins.target = addr + ins.len + imm32; ins.operands = to_hex(ins.target); break;
            case 0xe9: ins.mnemonic = "jmp"; ins.is_branch = true; ins.target = addr + ins.len + imm32; ins.operands = to_hex(ins.target); break;
            case 0xeb: ins.mnemonic = "jmp"; ins.is_branch = true; ins.target = addr + ins.len + imm8; ins.operands = to_hex(ins.target); break;
            case 0x90: ins.mnemonic = "nop"; break;
            case 0xcc: ins.mnemonic = "int3"; break;
            default: ins.mnemonic = "db"; ins.operands = to_hex(op); break;
        }
    }

    if (gen_pseudo_c_)
        ins.pseudo_c = pseudo_c_for(ins.mnemonic, ins.operands, addr, ins.target);

    return ins;
}

std::string x64disasm::format_mem(uint8_t mod, uint8_t rm, bool rex_b, int64_t disp, bool has_disp, bool rex_w, bool op66) {
    if (mod == 3) {
        return reg_name(rm, rex_b, rex_w, op66);  // fixed: use rm not reg
    }

    std::string result = "[";
    if (mod == 0 && rm == 5) {
        result += to_hex(disp);
    } else {
        result += reg_name(rm, rex_b, rex_w, op66);
        if (has_disp) {
            if (disp > 0) result += "+" + std::to_string(disp);
            else if (disp < 0) result += "-" + std::to_string(-disp);
        }
    }
    result += "]";
    return result;
}

std::string x64disasm::reg_name(uint8_t idx, bool rex_b, bool rex_w, bool op66) {
    static const char* r8[] = {"al","cl","dl","bl","spl","bpl","sil","dil",
                               "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"};
    static const char* r16[] = {"ax","cx","dx","bx","sp","bp","si","di",
                                "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"};
    static const char* r32[] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi",
                                "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"};
    static const char* r64[] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                                "r8","r9","r10","r11","r12","r13","r14","r15"};
    if (rex_w) return r64[idx | (rex_b ? 8 : 0)];
    if (op66) return r16[idx | (rex_b ? 8 : 0)];
    return r32[idx | (rex_b ? 8 : 0)];
}

std::string x64disasm::pseudo_c_for(const std::string& mnemonic, const std::string& operands, uint64_t addr, uint64_t target) {
    if (mnemonic == "mov") {
        size_t comma = operands.find(", ");
        if (comma != std::string::npos)
            return operands.substr(0, comma) + " = " + operands.substr(comma + 2) + ";";
    }
    if (mnemonic == "xor") {
        size_t comma = operands.find(", ");
        if (comma != std::string::npos && operands.substr(0, comma) == operands.substr(comma + 2))
            return operands.substr(0, comma) + " = 0;";
    }
    if (mnemonic == "add") {
        size_t comma = operands.find(", ");
        if (comma != std::string::npos)
            return operands.substr(0, comma) + " += " + operands.substr(comma + 2) + ";";
    }
    if (mnemonic == "sub") {
        size_t comma = operands.find(", ");
        if (comma != std::string::npos)
            return operands.substr(0, comma) + " -= " + operands.substr(comma + 2) + ";";
    }
    if (mnemonic == "ret") return "return;";
    if (mnemonic == "jmp") return "goto " + to_hex(target) + ";";
    if (mnemonic == "je" || mnemonic == "jz") return "if (/* equal */) goto " + to_hex(target) + ";";
    if (mnemonic == "jne" || mnemonic == "jnz") return "if (/* not equal */) goto " + to_hex(target) + ";";
    return "/* " + mnemonic + " " + operands + " */";
}

std::string x64disasm::to_hex(uint64_t val) {
    std::stringstream ss;
    ss << "0x" << std::hex << val;
    return ss.str();
}

std::vector<uint64_t> x64disasm::find_branches(const uint8_t* data, size_t size, uint64_t base_addr) {
    std::vector<uint64_t> targets;
    for (auto& ins : decode(data, size, base_addr))
        if (ins.is_branch && ins.target) targets.push_back(ins.target);
    std::sort(targets.begin(), targets.end());
    targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
    return targets;
}

void x64disasm::add_label(uint64_t addr, const std::string& name) { labels_[addr] = name; }
std::string x64disasm::get_label(uint64_t addr) {
    if (labels_.count(addr)) return labels_[addr];
    return to_hex(addr);
}

std::string x64disasm::to_pseudo_c(const std::vector<insn_t>& insns, const std::string& func_name) {
    std::stringstream ss;
    ss << "void " << func_name << "() {\n";
    for (const auto& ins : insns) {
        ss << "    ";
        if (ins.pseudo_c.empty()) ss << "/* " << ins.mnemonic << " " << ins.operands << " */";
        else ss << ins.pseudo_c;
        ss << "\n";
    }
    ss << "}\n";
    return ss.str();
}