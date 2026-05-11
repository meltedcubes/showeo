/*
 * Created by meltedcubes on 5/11/26, the c++ header executive for "x64decomp.h", apart of showeo library, licensed under MIT
 */
#include "../library/x64decomp.h"
#include <sstream>
#include <regex>
#include <algorithm>
#include <stack>
#include <functional>

struct x64decomp::expr_t {
    std::string text;
    bool is_const = false;
    uint64_t const_val = 0;
};

struct x64decomp::block_t {
    uint64_t start, end;
    std::vector<std::string> asm_ins;
    std::vector<expr_t> c_ins;
    std::vector<uint64_t> succ, pred;
    std::string label;
    bool visited = false;

    enum class type_t { NORMAL, COND, JUMP, SWITCH, RET } type = type_t::NORMAL;

    struct cond_t {
        std::string left, right, op;
        std::string to_string() const { return left + " " + op + " " + right; }
    } cond;

    struct loop_t {
        uint64_t header = 0, latch = 0;
        std::set<uint64_t> body;
        bool is_do_while = false;
    } loop;
};

x64decomp::x64decomp(uint64_t base) : base_addr_(base), func_start_(0), func_end_(0) {}

void x64decomp::set_function_bounds(uint64_t start, uint64_t end) {
    func_start_ = start;
    func_end_ = end;
}

std::string x64decomp::decompile(const insn_list_t& insns) {
    if (insns.empty()) return "";

    build_blocks(insns);
    analyze_stack(insns);
    translate_insns();
    detect_loops();
    build_cfg(insns);

    std::stringstream ss;
    ss << "#include <stdint.h>\n\n";
    ss << "// Decompiled with showeo v 1.0.0\n\n";
    ss << "// @ " << to_hex(func_start_) << " - " << to_hex(func_end_) << "\n";
    ss << "int64_t func() {\n";

    std::set<uint64_t> rendered;
    bool has_return = false;
    if (blocks_.count(func_start_))
        ss << render_block(func_start_, 1, has_return, rendered, false);

    if (!has_return) ss << "    return 0;\n";
    ss << "}\n\n";
    ss << "/* stats: " << blocks_.size() << " blocks, "
       << variables_.size() << " vars, frame: " << std::dec << frame_size_ << " bytes */\n";

    return ss.str();
}

void x64decomp::build_blocks(const insn_list_t& insns) {
    blocks_.clear();
    std::set<uint64_t> heads;
    if (!insns.empty()) heads.insert(insns[0].first);

    // find block boundaries
    for (size_t i = 0; i < insns.size(); i++) {
        const auto& mne = insns[i].second.first;
        const auto& ops = insns[i].second.second;

        if (mne == "jmp" || mne == "call" || mne == "ret") {
            if (i + 1 < insns.size()) heads.insert(insns[i + 1].first);
        }
        if (mne == "je" || mne == "jne" || mne == "jg" || mne == "jl" ||
            mne == "jge" || mne == "jle") {
            if (i + 1 < insns.size()) heads.insert(insns[i + 1].first);
            std::regex hex(R"(0x[0-9a-f]+)");
            std::smatch m;
            if (std::regex_search(ops, m, hex))
                heads.insert(std::stoull(m[0].str(), nullptr, 16));
        }
    }

    // create blocks
    uint64_t cur_start = insns[0].first;
    std::vector<std::string> cur_ins;
    for (size_t i = 0; i < insns.size(); i++) {
        uint64_t addr = insns[i].first;
        if (heads.count(addr) && addr != cur_start) {
            block_t b;
            b.start = cur_start;
            b.end = insns[i-1].first;
            b.asm_ins = cur_ins;
            blocks_[cur_start] = b;
            cur_start = addr;
            cur_ins.clear();
        }
        cur_ins.push_back(insns[i].second.first + " " + insns[i].second.second);
    }
    if (!cur_ins.empty()) {
        block_t b;
        b.start = cur_start;
        b.end = insns.back().first;
        b.asm_ins = cur_ins;
        blocks_[cur_start] = b;
    }

    // generate labels
    for (auto& [addr, b] : blocks_)
        b.label = new_label();
}

void x64decomp::analyze_stack(const insn_list_t& insns) {
    frame_size_ = 0;
    stack_vars_.clear();

    for (const auto& [addr, p] : insns) {
        const auto& mne = p.first;
        const auto& ops = p.second;

        if (mne == "sub" && ops.find("rsp, ") != std::string::npos) {
            size_t comma = ops.find(", ");
            if (comma != std::string::npos)
                frame_size_ = std::stoull(ops.substr(comma + 2), nullptr, 0);
        }

        std::regex pat(R"(\[rbp-([0-9a-fx]+)\])");
        std::smatch m;
        if (std::regex_search(ops, m, pat)) {
            int64_t off = std::stoull(m[1].str(), nullptr, 0);
            if (!stack_vars_.count(off)) {
                var_t v;
                v.name = new_var("local");
                v.offset = off;
                v.type = "int64_t";
                v.is_param = false;
                stack_vars_[off] = v;
                variables_[v.name] = v;
            }
        }
    }
}

void x64decomp::translate_insns() {
    reg_exprs_.clear();

    auto parse_reg = [&](const std::string& reg) -> expr_t {
        expr_t e;
        e.text = reg_to_c(reg);
        if (reg_exprs_.count(reg)) e = reg_exprs_[reg];
        return e;
    };

    auto parse_imm = [&](const std::string& s) -> expr_t {
        expr_t e;
        e.is_const = true;
        e.const_val = (s.find("0x") == 0) ? std::stoull(s, nullptr, 16) : std::stoull(s);
        e.text = s;
        return e;
    };

    for (auto& [addr, block] : blocks_) {
        for (const auto& ins : block.asm_ins) {
            std::regex pat(R"(([a-z]+)\s+(.*))");
            std::smatch m;
            if (!std::regex_search(ins, m, pat)) continue;

            std::string mne = m[1].str();
            std::string ops = m[2].str();

            size_t comma = ops.find(", ");
            std::string dest, src;
            if (comma != std::string::npos) {
                dest = ops.substr(0, comma);
                src = ops.substr(comma + 2);
            }

            expr_t e;

            if (mne == "mov" && !dest.empty()) {
                expr_t src_expr;
                if (src.find("0x") == 0 || src.find_first_not_of("0123456789") == std::string::npos)
                    src_expr = parse_imm(src);
                else if (src.find("[") != std::string::npos)
                    src_expr.text = src;  // simplify
                else
                    src_expr = parse_reg(src);

                if (dest.find("[") == std::string::npos)
                    reg_exprs_[dest] = src_expr;
                e.text = reg_to_c(dest) + " = " + src_expr.text + ";";
            }
            else if ((mne == "add" || mne == "sub") && !dest.empty()) {
                std::string op = (mne == "add") ? "+" : "-";
                expr_t left = parse_reg(dest);
                expr_t right = (src.find("0x") == 0) ? parse_imm(src) : parse_reg(src);

                std::stringstream ss;
                ss << left.text << " " << op << " " << right.text;
                e.text = reg_to_c(dest) + " = " + ss.str() + ";";
                if (dest.find("[") == std::string::npos) {
                    reg_exprs_[dest].text = ss.str();
                    reg_exprs_[dest].is_const = false;
                }
            }
            else if ((mne == "xor") && !dest.empty() && dest == src) {
                e.text = reg_to_c(dest) + " = 0;";
                if (dest.find("[") == std::string::npos) {
                    reg_exprs_[dest].text = "0";
                    reg_exprs_[dest].is_const = true;
                }
            }
            else if (mne != "cmp" && mne != "test") {
                e.text = "/* " + ins + " */";
            }

            if (!e.text.empty())
                block.c_ins.push_back(e);
        }
    }
}

void x64decomp::detect_loops() {
    std::map<uint64_t, int> dfs_num, low_link;
    std::stack<uint64_t> st;
    int counter = 0;

    std::function<void(uint64_t)> strongconnect = [&](uint64_t v) {
        dfs_num[v] = low_link[v] = ++counter;
        st.push(v);

        for (uint64_t w : blocks_[v].succ) {
            if (!dfs_num.count(w)) {
                strongconnect(w);
                low_link[v] = std::min(low_link[v], low_link[w]);
            } else {
                low_link[v] = std::min(low_link[v], dfs_num[w]);
            }
        }

        if (low_link[v] == dfs_num[v]) {
            std::set<uint64_t> scc;
            uint64_t w;
            do {
                w = st.top(); st.pop();
                scc.insert(w);
            } while (w != v);

            auto has_self = [&]() {
                return std::find(blocks_[v].succ.begin(), blocks_[v].succ.end(), v) != blocks_[v].succ.end();
            };

            if (scc.size() > 1 || has_self()) {
                for (uint64_t b : scc) {
                    blocks_[b].loop.header = v;
                    blocks_[b].loop.body = scc;
                }
                for (uint64_t b : scc) {
                    if (blocks_[b].succ.size() == 2) {
                        for (uint64_t s : blocks_[b].succ) {
                            if (!scc.count(s)) {
                                blocks_[v].loop.is_do_while = true;
                                blocks_[v].loop.latch = b;
                            }
                        }
                    }
                }
            }
        }
    };

    for (auto& [addr, _] : blocks_)
        if (!dfs_num.count(addr))
            strongconnect(addr);
}

void x64decomp::build_cfg(const insn_list_t& insns) {
    for (size_t i = 0; i < insns.size(); i++) {
        uint64_t addr = insns[i].first;
        const auto& mne = insns[i].second.first;
        const auto& ops = insns[i].second.second;

        if (!blocks_.count(addr)) continue;

        if (mne == "ret") {
            blocks_[addr].type = block_t::type_t::RET;
        }
        else if (mne == "jmp") {
            blocks_[addr].type = block_t::type_t::JUMP;
            std::regex hex(R"(0x[0-9a-f]+)");
            std::smatch m;
            if (std::regex_search(ops, m, hex)) {
                uint64_t t = std::stoull(m[0].str(), nullptr, 16);
                blocks_[addr].succ.push_back(t);
                blocks_[t].pred.push_back(addr);
            }
        }
        else if (mne == "je" || mne == "jne" || mne == "jg" || mne == "jl" ||
                 mne == "jge" || mne == "jle") {
            blocks_[addr].type = block_t::type_t::COND;

            // set condition from jump
            if (mne == "je") blocks_[addr].cond.op = "==";
            else if (mne == "jne") blocks_[addr].cond.op = "!=";
            else if (mne == "jg") blocks_[addr].cond.op = ">";
            else if (mne == "jge") blocks_[addr].cond.op = ">=";
            else if (mne == "jl") blocks_[addr].cond.op = "<";
            else if (mne == "jle") blocks_[addr].cond.op = "<=";

            blocks_[addr].cond.left = "cond";
            blocks_[addr].cond.right = "0";

            std::regex hex(R"(0x[0-9a-f]+)");
            std::smatch m;
            if (std::regex_search(ops, m, hex)) {
                uint64_t t = std::stoull(m[0].str(), nullptr, 16);
                blocks_[addr].succ.push_back(t);
                blocks_[t].pred.push_back(addr);

                if (i + 1 < insns.size()) {
                    uint64_t nxt = insns[i+1].first;
                    blocks_[addr].succ.push_back(nxt);
                    blocks_[nxt].pred.push_back(addr);
                }
            }
        }
        else if (i + 1 < insns.size()) {
            uint64_t nxt = insns[i+1].first;
            if (blocks_.count(nxt)) {
                blocks_[addr].succ.push_back(nxt);
                blocks_[nxt].pred.push_back(addr);
            }
        }
    }
}

std::string x64decomp::render_block(uint64_t addr, int indent, bool& has_ret,
                                    std::set<uint64_t>& rendered, bool in_loop) {
    if (!blocks_.count(addr) || rendered.count(addr)) return "";

    auto& b = blocks_[addr];
    if (b.loop.header == addr && !in_loop)
        return render_loop(addr, indent, has_ret, rendered);

    rendered.insert(addr);
    std::stringstream ss;
    std::string pad(indent * 4, ' ');

    if (b.pred.size() > 1)
        ss << pad << b.label << ":\n";

    for (const auto& e : b.c_ins)
        if (!e.text.empty())
            ss << pad << e.text << "\n";

    if (b.type == block_t::type_t::RET) {
        has_ret = true;
        ss << pad << "return" << (reg_exprs_.count("rax") ? " " + reg_exprs_["rax"].text : "") << ";\n";
    }
    else if (b.type == block_t::type_t::COND && b.succ.size() >= 2) {
        std::string then_b = render_block(b.succ[0], indent + 1, has_ret, rendered, in_loop);
        std::string else_b = render_block(b.succ[1], indent + 1, has_ret, rendered, in_loop);

        ss << pad << "if (" << b.cond.to_string() << ") {\n";
        ss << then_b;
        ss << pad << "}";
        if (!else_b.empty()) {
            ss << " else {\n" << else_b << pad << "}";
        }
        ss << "\n";
    }
    else if (b.succ.size() == 1) {
        uint64_t s = b.succ[0];
        if (b.loop.header == s && !in_loop) {}
        else if (s > addr)
            ss << render_block(s, indent, has_ret, rendered, in_loop);
        else if (!in_loop)
            ss << pad << "goto " << blocks_[s].label << ";\n";
    }

    return ss.str();
}

std::string x64decomp::render_loop(uint64_t addr, int indent, bool& has_ret,
                                   std::set<uint64_t>& rendered) {
    auto& b = blocks_[addr];
    std::stringstream ss;
    std::string pad(indent * 4, ' ');

    if (b.loop.is_do_while) {
        ss << pad << "do {\n";
        for (uint64_t blk : b.loop.body) {
            if (blk != b.loop.latch && !rendered.count(blk))
                ss << render_block(blk, indent + 1, has_ret, rendered, true);
        }
        ss << pad << "} while (" << b.cond.to_string() << ");\n";
    } else {
        ss << pad << "while (" << b.cond.to_string() << ") {\n";
        for (uint64_t blk : b.loop.body) {
            if (blk != addr && !rendered.count(blk))
                ss << render_block(blk, indent + 1, has_ret, rendered, true);
        }
        ss << pad << "}\n";
    }

    rendered.insert(b.loop.body.begin(), b.loop.body.end());
    for (uint64_t s : b.succ)
        if (!b.loop.body.count(s))
            ss << render_block(s, indent, has_ret, rendered, false);

    return ss.str();
}

// helper implementations
std::string x64decomp::new_var(const std::string& hint) {
    std::string name = hint.empty() ? "tmp" : hint;
    int c = 1;
    while (variables_.count(name)) {
        name = (hint.empty() ? "tmp" : hint) + "_" + std::to_string(c++);
    }
    return name;
}

std::string x64decomp::new_label() {
    return "L" + std::to_string(++label_counter_);
}

std::string x64decomp::to_hex(uint64_t val) {
    std::stringstream ss;
    ss << "0x" << std::hex << val;
    return ss.str();
}

std::string x64decomp::type_str(const std::string& reg) {
    if (reg == "al" || reg == "bl" || reg == "cl" || reg == "dl") return "uint8_t";
    if (reg == "ax" || reg == "bx" || reg == "cx" || reg == "dx") return "uint16_t";
    if (reg == "eax" || reg == "ebx" || reg == "ecx" || reg == "edx") return "uint32_t";
    return "uint64_t";
}

std::string x64decomp::reg_to_c(const std::string& reg) {
    static std::map<std::string, std::string> m = {
        {"rax", "ret"}, {"eax", "ret"}, {"rcx", "p1"}, {"ecx", "p1"},
        {"rdx", "p2"}, {"edx", "p2"}, {"r8", "p3"}, {"r9", "p4"},
        {"rsp", "sp"}, {"rbp", "fp"}, {"rdi", "a0"}, {"rsi", "a1"}
    };
    if (m.count(reg)) return m[reg];

    std::regex stack(R"(\[rbp-(\d+)\])");
    std::smatch match;
    if (std::regex_search(reg, match, stack)) {
        int64_t off = std::stoull(match[1].str());
        if (stack_vars_.count(off)) return stack_vars_[off].name;
        return "local_" + match[1].str();
    }
    return reg;
}