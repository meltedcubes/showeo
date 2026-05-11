/*
* Created by meltedcubes on 5/11/26, the c++ header for "x64dis", apart of showeo library, licensed under MIT
 */
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <regex>

struct insn_t {
    uint64_t addr;
    uint8_t bytes[15];
    uint8_t len;
    std::string mnemonic;
    std::string operands;
    uint64_t target;
    bool is_branch;
    bool is_conditional;
    std::string pseudo_c;
};

class x64disasm {
public:
    x64disasm();

    // main api
    std::vector<insn_t> decode(const uint8_t* data, size_t size, uint64_t base_addr = 0);
    std::vector<uint64_t> find_branches(const uint8_t* data, size_t size, uint64_t base_addr = 0);

    // settings
    void set_base(uint64_t base) { base_addr_ = base; }
    void set_pseudo_c(bool enable) { gen_pseudo_c_ = enable; }
    void add_label(uint64_t addr, const std::string& name);
    std::string get_label(uint64_t addr);

    // pseudo c output
    std::string to_pseudo_c(const std::vector<insn_t>& insns, const std::string& func_name = "func");

private:
    uint64_t base_addr_ = 0;
    bool gen_pseudo_c_ = false;
    std::map<uint64_t, std::string> labels_;

    // helpers for decoding
    insn_t decode_one(const uint8_t* code, size_t max_len, uint64_t addr);
    std::string format_mem(uint8_t mod, uint8_t rm, bool rex_b, int64_t disp, bool has_disp, bool rex_w, bool op66);
    std::string reg_name(uint8_t idx, bool rex_b, bool rex_w, bool op66);
    std::string pseudo_c_for(const std::string& mnemonic, const std::string& operands, uint64_t addr, uint64_t target);
    std::string to_hex(uint64_t val);
};