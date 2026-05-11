/*
* Created by meltedcubes on 5/11/26, the c++ header for "x64decomp", apart of showeo library, licensed under MIT
 */
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>

// instruction tuple: (addr, (mnemonic, operands))
using insn_list_t = std::vector<std::pair<uint64_t, std::pair<std::string, std::string>>>;

class x64decomp {
public:
    x64decomp(uint64_t base = 0);
    
    // main api
    std::string decompile(const insn_list_t& insns);
    void set_function_bounds(uint64_t start, uint64_t end);
    
    // analysis metadata
    size_t block_count() const { return blocks_.size(); }
    size_t var_count() const { return variables_.size(); }
    int64_t frame_size() const { return frame_size_; }

private:
    struct var_t {
        std::string name;
        std::string type;
        int64_t offset;
        bool is_param;
    };
    
    struct block_t;
    struct expr_t;
    
    uint64_t base_addr_, func_start_, func_end_;
    std::map<uint64_t, block_t> blocks_;
    std::map<std::string, var_t> variables_;
    std::map<int64_t, var_t> stack_vars_;
    std::map<std::string, expr_t> reg_exprs_;
    int64_t frame_size_ = 0;
    int var_counter_ = 0, label_counter_ = 0;
    
    // helpers
    std::string new_var(const std::string& hint);
    std::string new_label();
    std::string to_hex(uint64_t val);
    std::string type_str(const std::string& reg);
    std::string reg_to_c(const std::string& reg);
    
    // analysis passes
    void build_blocks(const insn_list_t& insns);
    void analyze_stack(const insn_list_t& insns);
    void translate_insns();
    void detect_loops();
    void build_cfg(const insn_list_t& insns);
    
    // codegen
    std::string render_block(uint64_t addr, int indent, bool& has_ret, 
                             std::set<uint64_t>& rendered, bool in_loop);
    std::string render_loop(uint64_t addr, int indent, bool& has_ret, 
                            std::set<uint64_t>& rendered);
};