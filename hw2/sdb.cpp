#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <map>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <climits>

#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>

#include <capstone/capstone.h>

#include <fstream>
#include <functional>

const std::string PROMPT = "(sdb) ";
pid_t child_pid = 0;
bool program_loaded = false;
uint64_t program_base_address = 0;
uint64_t program_actual_entry_point = 0;
int last_signal_received = 0;

user_regs_struct regs_cache;
bool regs_cache_valid = false;

struct Breakpoint {
    int     id;
    uint64_t address;
    uint8_t original_byte;
    bool    is_enabled;
};

std::map<uint64_t, Breakpoint> breakpoints_by_addr;
std::map<int, uint64_t>        breakpoint_addr_by_id;
int                             next_breakpoint_id = 0;

csh capstone_handle_global;

struct ExecutableSegment {
    uint64_t    start;
    uint64_t    end;
    std::string permissions;
    std::string path;
};
std::vector<ExecutableSegment> executable_segments_global;
std::string target_program_path_global;

bool  in_syscall_execution_mode    = false;
bool  is_next_syscall_stop_entry   = true;


long read_memory_byte_internal(pid_t pid, uint64_t addr) {
    uint64_t word_addr = addr & ~0x7ULL;
    errno = 0;
    long data = ptrace(PTRACE_PEEKDATA, pid, word_addr, nullptr);
    if (data == -1 && errno != 0) return -1;

    int offset = addr % 8;
    return (data >> (offset * 8)) & 0xff;
}

bool write_memory_byte_internal(pid_t pid, uint64_t addr, uint8_t byte_val) {
    uint64_t word_addr = addr & ~0x7ULL;
    errno = 0;
    long original_word = ptrace(PTRACE_PEEKDATA, pid, word_addr, nullptr);
    if (original_word == -1 && errno != 0) return false;

    int offset = addr % 8;
    uint64_t mask = ~(0xFFULL << (offset * 8));
    uint64_t new_word_val = (original_word & mask) |
                            ((uint64_t)byte_val << (offset * 8));

    errno = 0;
    if (ptrace(PTRACE_POKEDATA, pid, word_addr, new_word_val) == -1 && errno != 0)
        return false;

    return true;
}

bool get_current_registers() {
    if (!program_loaded || child_pid == 0) return false;
    memset(&regs_cache, 0, sizeof(regs_cache));  // Defensive zeroing

    if (ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs_cache) == -1) {
        perror("PTRACE_GETREGS");
        regs_cache_valid = false;
        return false;
    }

    regs_cache_valid = true;
    return true;
}

bool set_current_registers() {
    if (!program_loaded || child_pid == 0 || !regs_cache_valid) return false;

    if (ptrace(PTRACE_SETREGS, child_pid, nullptr, &regs_cache) == -1) {
        perror("PTRACE_SETREGS");
        return false;
    }

    return true;
}

void update_executable_info_and_load_addr(pid_t pid, const std::string& program_path_arg) {
    executable_segments_global.clear();
    program_base_address = 0;
    target_program_path_global = program_path_arg;

    char resolved_path_buf[PATH_MAX];
    std::string canonical_program_path;

    if (realpath(program_path_arg.c_str(), resolved_path_buf)) {
        canonical_program_path = resolved_path_buf;
    } else {
        canonical_program_path = program_path_arg;
    }

    std::ifstream maps_file("/proc/" + std::to_string(pid) + "/maps");
    std::string   line;
    bool          base_addr_candidate_found = false;

    while (std::getline(maps_file, line)) {
        std::istringstream iss(line);
        uint64_t start, end, file_offset;
        std::string perms, dev_str, inode_str, current_path_in_map;

        iss >> std::hex >> start;
        iss.ignore(1);
        iss >> std::hex >> end;
        iss >> perms >> std::hex >> file_offset >> dev_str >> inode_str;
        iss >> std::ws;
        std::getline(iss, current_path_in_map);

        if (perms.length() >= 3 && perms[2] == 'x') {
            executable_segments_global.push_back(
                { start, end, perms, current_path_in_map }
            );
        }
        if (current_path_in_map == canonical_program_path) {
            if (file_offset == 0) {
                program_base_address = start;
                base_addr_candidate_found = true;
            } else if (!base_addr_candidate_found) {
                program_base_address = start;
            }
        }
    }

    maps_file.close();
}

bool is_address_in_executable_region(uint64_t addr) {
    if (!program_loaded) return false;
    for (const auto& seg : executable_segments_global) {
        if (addr >= seg.start && addr < seg.end) {
            return true;
        }
    }
    return false;
}

void disassemble_and_print(uint64_t rip, size_t count) {
    if (!program_loaded || child_pid == 0) return;

    unsigned char instruction_buffer[16 * 5];
    size_t        bytes_collected = 0;
    uint64_t      addr_to_read    = rip;

    // 讀取可執行區段的 byte
    for (size_t i = 0; i < 15 * count && bytes_collected < sizeof(instruction_buffer); ++i) {
        bool in_exec = false;
        for (const auto& s : executable_segments_global) {
            if ((addr_to_read + i) >= s.start && (addr_to_read + i) < s.end) {
                in_exec = true;
                break;
            }
        }
        if (!in_exec) {
            if (i == 0) {
                std::cout << "** the address is out of the range of the executable region."
                          << std::endl;
                return;
            }
            break;
        }

        long byte_val = read_memory_byte_internal(child_pid, addr_to_read + i);
        if (byte_val == -1) {
            if (i == 0) {
                std::cout << "** the address is out of the range of the executable region."
                          << std::endl;
                return;
            }
            break;
        }

        auto bp_it = breakpoints_by_addr.find(addr_to_read + i);
        if (bp_it != breakpoints_by_addr.end() && bp_it->second.is_enabled) {
            instruction_buffer[bytes_collected++] = bp_it->second.original_byte;
        } else {
            instruction_buffer[bytes_collected++] =
                static_cast<unsigned char>(byte_val);
        }
    }

    if (bytes_collected == 0) {
        bool rip_in_exec = false;
        for (const auto& s : executable_segments_global) {
            if (rip >= s.start && rip < s.end) {
                rip_in_exec = true;
                break;
            }
        }
        if (!rip_in_exec) {
            std::cout << "** the address is out of the range of the executable region."
                      << std::endl;
        }
        return;
    }

    cs_insn* insn;
    size_t   num_dis = cs_disasm(capstone_handle_global,
                                 instruction_buffer,
                                 bytes_collected,
                                 rip,
                                 0,
                                 &insn);
    size_t printed_count = 0;

    if (num_dis > 0) {
        for (size_t i = 0; i < num_dis && printed_count < count; ++i) {
            bool instr_in_exec = false;
            for (const auto& s : executable_segments_global) {
                if (insn[i].address >= s.start && insn[i].address < s.end) {
                    instr_in_exec = true;
                    break;
                }
            }
            if (!instr_in_exec) {
                std::cout << "** the address is out of the range of the executable region."
                          << std::endl;
                break;
            }

            std::ostringstream lss;
            lss << "      " << std::hex << insn[i].address << ":";
            std::string bstr;
            for (int j = 0; j < insn[i].size; ++j) {
                char hb[4];
                sprintf(hb, " %02x", insn[i].bytes[j]);
                bstr += hb;
            }
            lss << std::left << std::setw(24) << bstr << insn[i].mnemonic;
            if (insn[i].op_str[0] != '\0') {
                lss << " " << insn[i].op_str;
            }

            std::cout << lss.str() << std::endl;
            printed_count++;
        }
        cs_free(insn, num_dis);

        // 檢查是否還有指令超出範圍
        if (printed_count < count && printed_count > 0) {
            uint64_t next_addr =
                insn[printed_count - 1].address + insn[printed_count - 1].size;
            bool next_in_exec = false;
            for (const auto& s : executable_segments_global) {
                if (next_addr >= s.start && next_addr < s.end) {
                    next_in_exec = true;
                    break;
                }
            }
            if (!next_in_exec) {
                std::cout << "** the address is out of the range of the executable region."
                          << std::endl;
            }
        }
    } else {
        bool rip_in_exec = false;
        for (const auto& s : executable_segments_global) {
            if (rip >= s.start && rip < s.end) {
                rip_in_exec = true;
                break;
            }
        }
        if (rip_in_exec) {
            std::cout << "** the address is out of the range of the executable region."
                      << std::endl;
        }
    }
}

void ptrace_continue_execution(pid_t pid) {
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
}

void ptrace_single_step(pid_t pid) {
    ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);
}

void ptrace_syscall_step(pid_t pid) {
    ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
}

bool wait_for_process_event(int& status_code_out) {
    if (child_pid == 0) return false;

    if (waitpid(child_pid, &status_code_out, 0) == -1) {
        program_loaded = false;
        child_pid = 0;
        return false;
    }

    regs_cache_valid = false;

    if (WIFEXITED(status_code_out)) {
        std::cout << "** the target program terminated." << std::endl;
        program_loaded = false;
        child_pid = 0;
        return false;
    }

    if (WIFSIGNALED(status_code_out)) {
        std::cout << "** the target program terminated "
                  << "(killed by signal " << WTERMSIG(status_code_out)
                  << ")." << std::endl;
        program_loaded = false;
        child_pid = 0;
        return false;
    }

    if (WIFSTOPPED(status_code_out)) {
        last_signal_received = WSTOPSIG(status_code_out);
        get_current_registers();

        // Syscall entry/exit 處理
        if (in_syscall_execution_mode &&
            (last_signal_received == (SIGTRAP | 0x80))) {
            uint64_t syscall_instruction_addr = regs_cache.rip - 2;
            if (is_next_syscall_stop_entry) {
                std::cout << "** enter a syscall(" << regs_cache.orig_rax
                          << ") at 0x" << std::hex << syscall_instruction_addr
                          << "." << std::endl;
                is_next_syscall_stop_entry = false;
            } else {
                std::cout << "** leave a syscall(" << regs_cache.orig_rax
                          << ") = " << std::dec << (long long)regs_cache.rax
                          << " at 0x" << std::hex
                          << syscall_instruction_addr << "." << std::endl;
                is_next_syscall_stop_entry = true;
                in_syscall_execution_mode   = false;
            }
            regs_cache.rip = syscall_instruction_addr;  // For disassembly
            return true;
        }
        // Breakpoint 處理
        else if (last_signal_received == SIGTRAP) {
            uint64_t addr_before_rip = regs_cache.rip - 1;
            auto     bp_iter_prev   = breakpoints_by_addr.find(addr_before_rip);
            auto     bp_iter_curr   = breakpoints_by_addr.find(regs_cache.rip);

            uint64_t actual_bp_addr = 0;
            bool     bp_found       = false;

            if (bp_iter_prev != breakpoints_by_addr.end() &&
                bp_iter_prev->second.is_enabled) {
                actual_bp_addr = addr_before_rip;
                bp_found       = true;
            } else if (bp_iter_curr != breakpoints_by_addr.end() &&
                       bp_iter_curr->second.is_enabled) {
                actual_bp_addr = regs_cache.rip;
                bp_found       = true;
            }

            if (bp_found) {
                if (in_syscall_execution_mode) {
                    in_syscall_execution_mode  = false;
                    is_next_syscall_stop_entry = true;
                }
                std::cout << "** hit a breakpoint at 0x"
                          << std::hex << actual_bp_addr << "." << std::endl;
                regs_cache.rip = actual_bp_addr;
                set_current_registers();
            } else {
                if (in_syscall_execution_mode) {
                    in_syscall_execution_mode  = false;
                    is_next_syscall_stop_entry = true;
                }
            }
            return true;
        } else {
            if (in_syscall_execution_mode) {
                in_syscall_execution_mode  = false;
                is_next_syscall_stop_entry = true;
            }
            return true;
        }
    }

    return false;
}

bool enable_bp_at_addr(uint64_t addr) {
    auto it = breakpoints_by_addr.find(addr);
    if (it == breakpoints_by_addr.end()) return false;
    if (it->second.is_enabled)       return true;

    long orig_byte = read_memory_byte_internal(child_pid, addr);
    if (orig_byte == -1) return false;

    it->second.original_byte = static_cast<uint8_t>(orig_byte);
    if (!write_memory_byte_internal(child_pid, addr, 0xCC)) return false;

    it->second.is_enabled = true;
    return true;
}

bool disable_bp_at_addr(uint64_t addr) {
    auto it = breakpoints_by_addr.find(addr);
    if (it == breakpoints_by_addr.end() || !it->second.is_enabled) return true;

    write_memory_byte_internal(child_pid, addr, it->second.original_byte);
    it->second.is_enabled = false;
    return true;
}

bool step_over_instruction_at_breakpoint() {
    if (!program_loaded || !regs_cache_valid) return false;

    auto bp_it = breakpoints_by_addr.find(regs_cache.rip);
    if (bp_it != breakpoints_by_addr.end() && bp_it->second.is_enabled) {
        disable_bp_at_addr(regs_cache.rip);
        ptrace_single_step(child_pid);

        int status;
        if (waitpid(child_pid, &status, 0) == -1) {
            enable_bp_at_addr(regs_cache.rip);
            program_loaded = false;
            child_pid      = 0;
            return false;
        }

        get_current_registers();
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            wait_for_process_event(status);
            return false;
        }

        enable_bp_at_addr(bp_it->first);
        return true;
    }

    return false;
}

uint64_t get_elf_entry_offset_from_readelf(const std::string& path) {
    std::string cmd = "readelf -h " + path +
                      " 2>/dev/null | grep 'Entry point address:'";
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) return 0;

    char        buf[256];
    std::string r;
    while (fgets(buf, sizeof(buf), p) != nullptr) {
        r += buf;
    }
    pclose(p);

    size_t pos = r.find("0x");
    if (pos != std::string::npos) {
        try {
            return std::stoull(r.substr(pos), nullptr, 16);
        } catch (...) {
            return 0;
        }
    }
    return 0;
}

bool check_elf_is_dynamic_from_readelf(const std::string& path) {
    std::string cmd = "readelf -h " + path +
                      " 2>/dev/null | grep 'Type:'";
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) return false;

    char        buf[256];
    std::string r;
    while (fgets(buf, sizeof(buf), p) != nullptr) {
        r += buf;
    }
    pclose(p);

    return r.find("DYN") != std::string::npos;
}

void handle_load_cmd(const std::vector<std::string>& args) {
    if (args.empty()) return;

    // 清除先前狀態
    if (program_loaded && child_pid != 0) {
        kill(child_pid, SIGKILL);
        waitpid(child_pid, nullptr, 0);
        child_pid = 0;
        program_loaded = false;
        breakpoints_by_addr.clear();
        breakpoint_addr_by_id.clear();
        next_breakpoint_id = 0;
        executable_segments_global.clear();
        program_base_address = 0;
        program_actual_entry_point = 0;
        regs_cache_valid = false;
    }

    std::string prog_path = args[0];
    if (access(prog_path.c_str(), X_OK) == -1) {
        std::cout << "** program '" << prog_path
                  << "' not found or not executable." << std::endl;
        return;
    }

    child_pid = fork();
    if (child_pid == 0) {
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        execl(prog_path.c_str(), prog_path.c_str(), (char*)nullptr);
        exit(1);
    } else if (child_pid > 0) {
        int status;
        waitpid(child_pid, &status, 0);
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            std::cout << "** program '" << prog_path
                      << "' failed to start." << std::endl;
            child_pid = 0;
            return;
        }

        ptrace(PTRACE_SETOPTIONS, child_pid, 0,
               PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL);
        program_loaded = true;

        update_executable_info_and_load_addr(child_pid, prog_path);
        get_current_registers();

        uint64_t elf_entry = get_elf_entry_offset_from_readelf(prog_path);
        bool     is_dyn   = check_elf_is_dynamic_from_readelf(prog_path);

        if (is_dyn) {
            if (program_base_address != 0 && elf_entry != 0) {
                uint64_t target_e = program_base_address + elf_entry;
                program_actual_entry_point = target_e;

                if (regs_cache.rip != target_e) {
                    long ob = read_memory_byte_internal(child_pid, target_e);
                    if (ob != -1) {
                        write_memory_byte_internal(child_pid, target_e, 0xCC);
                        ptrace_continue_execution(child_pid);
                        waitpid(child_pid, &status, 0);

                        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
                            get_current_registers();
                            if (regs_cache.rip - 1 == target_e) {
                                regs_cache.rip = target_e;
                                set_current_registers();
                            }
                            program_actual_entry_point = regs_cache.rip;
                        } else {
                            wait_for_process_event(status);
                            return;
                        }

                        write_memory_byte_internal(
                            child_pid,
                            target_e,
                            static_cast<uint8_t>(ob)
                        );
                    } else {
                        program_actual_entry_point = regs_cache.rip;
                    }
                } else {
                    program_actual_entry_point = regs_cache.rip;
                }
            } else {
                program_actual_entry_point = regs_cache.rip;
            }
        } else {
            program_actual_entry_point = regs_cache.rip;
        }

        std::cout << "** program '" << prog_path
                  << "' loaded. entry point: 0x"
                  << std::hex << program_actual_entry_point << "."
                  << std::endl;

        disassemble_and_print(regs_cache.rip, 5);
    }
}

void execute_and_report(
    const std::string& cmd_type,
    const std::function<void(pid_t)>& ptrace_action
) {
    if (!program_loaded) {
        std::cout << "** please load a program first." << std::endl;
        return;
    }

    if (cmd_type == "syscall") {
        if (!in_syscall_execution_mode) {
            is_next_syscall_stop_entry = true;
        }
        in_syscall_execution_mode = true;
    } else {
        if (in_syscall_execution_mode) {
            in_syscall_execution_mode  = false;
            is_next_syscall_stop_entry = true;
        }
    }

    if (regs_cache_valid) {
        auto bp_it = breakpoints_by_addr.find(regs_cache.rip);
        if (bp_it != breakpoints_by_addr.end() && bp_it->second.is_enabled) {
            if (step_over_instruction_at_breakpoint()) {
                if (cmd_type == "si" && program_loaded) {
                    disassemble_and_print(regs_cache.rip, 5);
                }
                return;
            }
            return;
        }
    }

    ptrace_action(child_pid);
    int status;
    if (wait_for_process_event(status) && program_loaded) {
        disassemble_and_print(regs_cache.rip, 5);
    }
}

void handle_si_cmd()      { execute_and_report("si",      ptrace_single_step); }
void handle_cont_cmd()    { execute_and_report("cont",    ptrace_continue_execution); }
void handle_syscall_cmd_wrapper() {
    execute_and_report("syscall", ptrace_syscall_step);
}

void handle_info_cmd(const std::vector<std::string>& args) {
    if (!program_loaded) {
        std::cout << "** please load a program first." << std::endl;
        return;
    }
    if (args.empty()) return;

    if (args[0] == "reg") {
        if (!get_current_registers()) {
            std::cerr << "Failed to get registers for info reg." << std::endl;
            return;
        }

        printf("$rip  0x%016llx\n", regs_cache.rip);
        printf("$rax  0x%016llx\n", regs_cache.rax);

        const char* names[] = {
            "$rax","$rbx","$rcx","$rdx","$rsi","$rdi","$rbp","$rsp",
            "$r8","$r9","$r10","$r11","$r12","$r13","$r14","$r15",
            "$rip","$eflags"
        };
        uint64_t vals_arr[] = {
            regs_cache.rax, regs_cache.rbx, regs_cache.rcx, regs_cache.rdx,
            regs_cache.rsi, regs_cache.rdi, regs_cache.rbp, regs_cache.rsp,
            regs_cache.r8,  regs_cache.r9,  regs_cache.r10,regs_cache.r11,
            regs_cache.r12, regs_cache.r13, regs_cache.r14,regs_cache.r15,
            regs_cache.rip, regs_cache.eflags
        };

        for (int i = 0; i < 18; ++i) {
            std::cout << std::left << std::setw(5) << names[i] << " 0x"
                      << std::hex << std::setfill('0') << std::setw(16)
                      << std::right << vals_arr[i]
                      << std::setfill(' ') << std::left;

            if ((i + 1) % 3 == 0 || i == 17) std::cout << std::endl;
            else                               std::cout << "    ";
        }
    }
    else if (args[0] == "break") {
        if (breakpoint_addr_by_id.empty()) {
            std::cout << "** no breakpoints." << std::endl;
        } else {
            std::cout << "Num     Address" << std::endl;
            std::vector<std::pair<int, uint64_t>> sbp;
            for (const auto& p : breakpoint_addr_by_id) {
                if (breakpoints_by_addr.count(p.second))
                    sbp.push_back(p);
            }
            std::sort(sbp.begin(), sbp.end());
            for (const auto& p : sbp) {
                std::cout << std::left << std::setw(8) << p.first
                          << "0x" << std::hex << p.second << std::endl;
            }
        }
    }
}

void add_new_breakpoint(uint64_t eff_addr) {
    if (!is_address_in_executable_region(eff_addr)) {
        std::cout << "** the target address is not valid." << std::endl;
        return;
    }

    Breakpoint bp;
    bp.id            = next_breakpoint_id++;
    bp.address       = eff_addr;
    bp.is_enabled    = false;

    breakpoints_by_addr[eff_addr]    = bp;
    breakpoint_addr_by_id[bp.id]     = eff_addr;

    if (!enable_bp_at_addr(eff_addr)) {
        std::cout << "** the target address is not valid." << std::endl;
        breakpoints_by_addr.erase(eff_addr);
        breakpoint_addr_by_id.erase(bp.id);
        next_breakpoint_id--;
        return;
    }

    std::cout << "** set a breakpoint at 0x"
              << std::hex << eff_addr << "." << std::endl;
}

void handle_break_cmd(const std::vector<std::string>& args) {
    if (!program_loaded) {
        std::cout << "** please load a program first." << std::endl;
        return;
    }
    if (args.empty()) return;

    uint64_t a;
    try {
        a = std::stoull(args[0], nullptr, 16);
    } catch (...) {
        std::cout << "** the target address is not valid." << std::endl;
        return;
    }

    add_new_breakpoint(a);
}

void handle_breakrva_cmd(const std::vector<std::string>& args) {
    if (!program_loaded) {
        std::cout << "** please load a program first." << std::endl;
        return;
    }
    if (args.empty()) return;

    uint64_t o;
    try {
        o = std::stoull(args[0], nullptr, 16);
    } catch (...) {
        std::cout << "** the target address is not valid." << std::endl;
        return;
    }

    if (program_base_address == 0) {
        std::cout << "** the target address is not valid."
                  << " (Base address not determined)" << std::endl;
        return;
    }

    add_new_breakpoint(program_base_address + o);
}

void handle_delete_cmd(const std::vector<std::string>& args) {
    if (!program_loaded) {
        std::cout << "** please load a program first." << std::endl;
        return;
    }
    if (args.empty()) return;

    int id;
    try {
        id = std::stoi(args[0]);
    } catch (...) {
        std::cout << "** breakpoint " << args[0] << " does not exist." << std::endl;
        return;
    }

    auto it = breakpoint_addr_by_id.find(id);
    if (it == breakpoint_addr_by_id.end()) {
        std::cout << "** breakpoint " << id << " does not exist." << std::endl;
        return;
    }

    uint64_t adr = it->second;
    if (breakpoints_by_addr.count(adr) &&
        breakpoints_by_addr[adr].id == id) {
        disable_bp_at_addr(adr);
        breakpoints_by_addr.erase(adr);
    }

    breakpoint_addr_by_id.erase(it);
    std::cout << "** delete breakpoint " << id << "." << std::endl;
}

void handle_patch_cmd(const std::vector<std::string>& args) {
    if (!program_loaded) {
        std::cout << "** please load a program first." << std::endl;
        return;
    }
    if (args.size() < 2) return;

    uint64_t adr_p;
    try {
        adr_p = std::stoull(args[0], nullptr, 16);
    } catch (...) {
        std::cout << "** the target address is not valid." << std::endl;
        return;
    }

    const std::string& hstr = args[1];
    if (hstr.empty() || hstr.length() % 2 != 0 || hstr.length() > 2048) {
        std::cout << "** the target address is not valid." << std::endl;
        return;
    }

    std::vector<uint8_t> bvec;
    for (size_t i = 0; i < hstr.length(); i += 2) {
        try {
            bvec.push_back(static_cast<uint8_t>(
                std::stoull(hstr.substr(i, 2), nullptr, 16)
            ));
        } catch (...) {
            std::cout << "** the target address is not valid." << std::endl;
            return;
        }
    }

    for (size_t i = 0; i < bvec.size(); ++i) {
        if (!is_address_in_executable_region(adr_p + i)) {
            std::cout << "** the target address is not valid." << std::endl;
            return;
        }
    }

    for (size_t i = 0; i < bvec.size(); ++i) {
        uint64_t adr_i = adr_p + i;
        auto     bp_it = breakpoints_by_addr.find(adr_i);

        bool    bpen  = false;
        uint8_t ob_bp = 0;
        if (bp_it != breakpoints_by_addr.end() && bp_it->second.is_enabled) {
            bpen   = true;
            ob_bp  = bp_it->second.original_byte;
            disable_bp_at_addr(adr_i);
        }

        if (!write_memory_byte_internal(child_pid, adr_i, bvec[i])) {
            std::cout << "** the target address is not valid." << std::endl;
            if (bpen) {
                write_memory_byte_internal(child_pid, adr_i, ob_bp);
                enable_bp_at_addr(adr_i);
            }
            return;
        }

        if (bpen) {
            bp_it->second.original_byte = bvec[i];
            if (!write_memory_byte_internal(child_pid, adr_i, 0xCC)) {
                bp_it->second.is_enabled = false;
            } else {
                bp_it->second.is_enabled = true;
            }
        }
    }

    std::cout << "** patched memory at 0x"
              << std::hex << adr_p << "." << std::endl;
}

void sdb_initialize() {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_handle_global) != CS_ERR_OK) {
        std::cerr << "FATAL: Capstone init failed." << std::endl;
        exit(1);
    }
}

void sdb_cleanup() {
    if (capstone_handle_global != 0) {
        cs_close(&capstone_handle_global);
    }
    if (child_pid != 0 && program_loaded) {
        kill(child_pid, SIGKILL);
        waitpid(child_pid, nullptr, 0);
    }
}

std::vector<std::string> tokenize_input_line(const std::string& line) {
    std::vector<std::string> t;
    std::string              tk;
    std::istringstream       s(line);

    while (s >> tk) {
        t.push_back(tk);
    }
    return t;
}

int main(int argc, char* argv[]) {
    sdb_initialize();
    std::atexit(sdb_cleanup);

    if (argc > 1) {
        handle_load_cmd({ argv[1] });
    }

    std::string line_input;
    while (true) {
        std::cout << PROMPT << std::flush;
        if (!std::getline(std::cin, line_input)) break;
        if (line_input.empty()) continue;

        auto tokens = tokenize_input_line(line_input);
        if (tokens.empty()) continue;

        const std::string& cmd      = tokens[0];
        std::vector<std::string> args(tokens.begin() + 1, tokens.end());

        if (cmd == "load")      handle_load_cmd(args);
        else if (cmd == "si")   handle_si_cmd();
        else if (cmd == "cont") handle_cont_cmd();
        else if (cmd == "info") handle_info_cmd(args);
        else if (cmd == "break")    handle_break_cmd(args);
        else if (cmd == "breakrva") handle_breakrva_cmd(args);
        else if (cmd == "delete")   handle_delete_cmd(args);
        else if (cmd == "patch")    handle_patch_cmd(args);
        else if (cmd == "syscall")  handle_syscall_cmd_wrapper();
        else if (cmd == "exit" || cmd == "quit" || cmd == "q")
            break;
        else {
            if (!program_loaded && cmd != "load") {
                std::cout << "** please load a program first." << std::endl;
            } else {
                std::cout << "** Unknown command: " << cmd << std::endl;
            }
        }
    }

    return 0;
}
