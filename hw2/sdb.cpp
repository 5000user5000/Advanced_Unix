// 第二題差 reg 這邊,ex3 有過! 最後一題差一點
// sdb.cpp
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
    int id;
    uint64_t address;
    uint8_t original_byte;
    bool is_enabled;
};

std::map<uint64_t, Breakpoint> breakpoints_by_addr;
std::map<int, uint64_t> breakpoint_addr_by_id;
int next_breakpoint_id = 0;

csh capstone_handle_global;

struct ExecutableSegment {
    uint64_t start;
    uint64_t end;
    std::string permissions;
    std::string path;
};
std::vector<ExecutableSegment> executable_segments_global;
std::string target_program_path_global;

bool in_syscall_execution_mode = false;
bool is_next_syscall_stop_entry = true;

long read_memory_byte_internal(pid_t pid, uint64_t addr) {
    uint64_t word_addr = addr & ~0x7ULL;
    errno = 0;
    long data = ptrace(PTRACE_PEEKDATA, pid, word_addr, nullptr);
    if (data == -1 && errno != 0) { return -1; }
    int offset = addr % 8;
    return (data >> (offset * 8)) & 0xff;
}

bool write_memory_byte_internal(pid_t pid, uint64_t addr, uint8_t byte_val) {
    uint64_t word_addr = addr & ~0x7ULL;
    errno = 0;
    long original_word = ptrace(PTRACE_PEEKDATA, pid, word_addr, nullptr);
    if (original_word == -1 && errno != 0) { return false; }
    int offset = addr % 8;
    uint64_t mask = ~(0xFFULL << (offset * 8));
    uint64_t new_word_val = (original_word & mask) | ((uint64_t)byte_val << (offset * 8));
    errno = 0;
    if (ptrace(PTRACE_POKEDATA, pid, word_addr, new_word_val) == -1 && errno != 0) { return false; }
    return true;
}

bool get_current_registers() {
    if (!program_loaded || child_pid == 0) return false;
    if (ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs_cache) == -1) {
        perror("PTRACE_GETREGS"); // Add perror for diagnostics
        regs_cache_valid = false;
        return false;
    }
    regs_cache_valid = true;
    return true;
}

bool set_current_registers() {
    if (!program_loaded || child_pid == 0 || !regs_cache_valid) return false;
    if (ptrace(PTRACE_SETREGS, child_pid, nullptr, &regs_cache) == -1) {
        perror("PTRACE_SETREGS"); // Add perror
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
    } else { canonical_program_path = program_path_arg; }

    std::ifstream maps_file("/proc/" + std::to_string(pid) + "/maps");
    std::string line;
    bool base_addr_candidate_found = false;
    while (std::getline(maps_file, line)) {
        std::istringstream iss(line);
        uint64_t start, end, file_offset;
        std::string perms, dev_str, inode_str, current_path_in_map;
        iss >> std::hex >> start; iss.ignore(1); iss >> std::hex >> end;
        iss >> perms >> std::hex >> file_offset >> dev_str >> inode_str;
        iss >> std::ws; std::getline(iss, current_path_in_map);
        if (perms.length() >= 3 && perms[2] == 'x') {
            executable_segments_global.push_back({start, end, perms, current_path_in_map});
        }
        if (current_path_in_map == canonical_program_path) {
            if (file_offset == 0) {
                 program_base_address = start; base_addr_candidate_found = true;
            } else if (!base_addr_candidate_found) { program_base_address = start; }
        }
    }
    maps_file.close();
    // std::cerr << "[DEBUG] update_executable_info_and_load_addr for " << canonical_program_path << std::endl;
    // std::cerr << "[DEBUG] Determined program_base_address: 0x" << std::hex << program_base_address << std::dec << std::endl;
    // std::cerr << "[DEBUG] Executable Segments Found:" << std::endl;
    // for (const auto& seg : executable_segments_global) {
    //     std::cerr << "[DEBUG]   0x" << std::hex << seg.start << "-0x" << seg.end << " " << seg.permissions << " " << seg.path << std::dec << std::endl;
    // }
}

bool is_address_in_executable_region(uint64_t addr) {
    if (!program_loaded) return false;
    for (const auto& seg : executable_segments_global) {
        if (addr >= seg.start && addr < seg.end) { return true; }
    }
    return false;
}

void disassemble_and_print(uint64_t rip, size_t count) {
    if (!program_loaded || child_pid == 0) return;
    unsigned char instruction_buffer[16 * 5]; size_t bytes_collected = 0;
    uint64_t addr_to_read = rip;
    for (size_t i = 0; i < 15 * count && bytes_collected < sizeof(instruction_buffer); ++i) {
        bool current_byte_in_any_exec_segment = false;
        for (const auto& seg : executable_segments_global) {
            if ((addr_to_read + i) >= seg.start && (addr_to_read + i) < seg.end) {
                current_byte_in_any_exec_segment = true; break;
            }
        }
        if (!current_byte_in_any_exec_segment) {
            if (i == 0) { std::cout << "** the address is out of the range of the executable region." << std::endl; return; }
            break;
        }
        long byte_val = read_memory_byte_internal(child_pid, addr_to_read + i);
        if (byte_val == -1) {
            if (i == 0) { std::cout << "** the address is out of the range of the executable region." << std::endl; return; }
            break;
        }
        auto bp_it = breakpoints_by_addr.find(addr_to_read + i);
        if (bp_it != breakpoints_by_addr.end() && bp_it->second.is_enabled) {
            instruction_buffer[bytes_collected++] = bp_it->second.original_byte;
        } else { instruction_buffer[bytes_collected++] = static_cast<unsigned char>(byte_val); }
    }
    if (bytes_collected == 0) {
        bool rip_in_any_exec_segment = false;
        for (const auto& seg : executable_segments_global) { if (rip >= seg.start && rip < seg.end) { rip_in_any_exec_segment = true; break; } }
        if(!rip_in_any_exec_segment){ std::cout << "** the address is out of the range of the executable region." << std::endl; }
        else if (bytes_collected == 0 && rip_in_any_exec_segment) { std::cout << "** the address is out of the range of the executable region." << std::endl; }
        return;
    }
    cs_insn *insn; size_t num_disassembled = cs_disasm(capstone_handle_global, instruction_buffer, bytes_collected, rip, 0, &insn);
    size_t printed_count = 0;
    if (num_disassembled > 0) {
        for (size_t i = 0; i < num_disassembled && printed_count < count; ++i) {
            bool instr_addr_in_any_exec_segment = false;
            for (const auto& seg : executable_segments_global) { if (insn[i].address >= seg.start && insn[i].address < seg.end) { instr_addr_in_any_exec_segment = true; break; } }
            if (!instr_addr_in_any_exec_segment) { std::cout << "** the address is out of the range of the executable region." << std::endl; break; }
            std::ostringstream line_ss; line_ss << "      " << std::hex << insn[i].address << ":";
            std::string byte_str; for (int j = 0; j < insn[i].size; ++j) { char hb[4]; sprintf(hb, " %02x", insn[i].bytes[j]); byte_str += hb; }
            line_ss << std::left << std::setw(24) << byte_str << insn[i].mnemonic;
            if (insn[i].op_str[0] != '\0') { line_ss << " " << insn[i].op_str; }
            std::cout << line_ss.str() << std::endl; printed_count++;
        }
        cs_free(insn, num_disassembled);
        if (printed_count < count && printed_count > 0) {
            uint64_t next_addr = insn[printed_count-1].address + insn[printed_count-1].size;
            bool next_in_exec = false; for (const auto& s : executable_segments_global) { if (next_addr>=s.start && next_addr<s.end) {next_in_exec=true; break;}}
            if (!next_in_exec) { std::cout << "** the address is out of the range of the executable region." << std::endl; }
        } else if (printed_count == 0) {
            bool rip_in_exec = false; for(const auto&s : executable_segments_global){if(rip>=s.start && rip<s.end){rip_in_exec=true;break;}}
            if (rip_in_exec){ std::cout << "** the address is out of the range of the executable region." << std::endl; }
        }
    } else {
        bool rip_in_exec = false; for(const auto&s : executable_segments_global){if(rip>=s.start && rip<s.end){rip_in_exec=true;break;}}
        if (rip_in_exec) { std::cout << "** the address is out of the range of the executable region." << std::endl; }
    }
}

void ptrace_continue_execution(pid_t pid) { if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) == -1) {} }
void ptrace_single_step(pid_t pid) { if (ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr) == -1) { } }
void ptrace_syscall_step(pid_t pid) { if (ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr) == -1) { } }

bool wait_for_process_event(int& status_code_out) {
    if (child_pid == 0) return false;
    if (waitpid(child_pid, &status_code_out, 0) == -1) { program_loaded = false; child_pid = 0; return false; }
    regs_cache_valid = false;
    if (WIFEXITED(status_code_out)) { std::cout << "** the target program terminated." << std::endl; program_loaded = false; child_pid = 0; return false; }
    if (WIFSIGNALED(status_code_out)) { std::cout << "** the target program terminated (killed by signal " << WTERMSIG(status_code_out) << ")." << std::endl; program_loaded = false; child_pid = 0; return false; }
    
    if (WIFSTOPPED(status_code_out)) {
        last_signal_received = WSTOPSIG(status_code_out);
        get_current_registers(); // Get registers immediately

        if (in_syscall_execution_mode && (last_signal_received == (SIGTRAP | 0x80))) {
            uint64_t syscall_instruction_addr = regs_cache.rip - 2; // 'syscall' is 2 bytes
            
            if (is_next_syscall_stop_entry) {
                std::cout << "** enter a syscall(" << regs_cache.orig_rax << ") at 0x" << std::hex << syscall_instruction_addr << "." << std::endl;
                is_next_syscall_stop_entry = false; // Next stop for this syscall will be an exit
            } else {
                std::cout << "** leave a syscall(" << regs_cache.orig_rax << ") = " << std::dec << (long long)regs_cache.rax << " at 0x" << std::hex << syscall_instruction_addr << "." << std::endl;
                is_next_syscall_stop_entry = true;  // Reset for a *new* potential 'syscall' cmd
                in_syscall_execution_mode = false; // This syscall pair is complete
            }
            // Adjust RIP for disassembly to show the syscall instruction itself
            regs_cache.rip = syscall_instruction_addr;
            // No need to PTRACE_SETREGS here, child is already past/at syscall. This is for debugger's view.
            // However, if we are to single step from here, child's RIP needs to be accurate.
            // For now, disassembly uses this adjusted regs_cache.rip.
            return true;
        }
        else if (last_signal_received == SIGTRAP) {
            uint64_t addr_before_rip = regs_cache.rip - 1;
            auto bp_iter_prev = breakpoints_by_addr.find(addr_before_rip);
            auto bp_iter_curr = breakpoints_by_addr.find(regs_cache.rip); // Should not happen for 0xcc
            uint64_t actual_bp_addr = 0; bool bp_found = false;

            if (bp_iter_prev != breakpoints_by_addr.end() && bp_iter_prev->second.is_enabled) {
                actual_bp_addr = addr_before_rip; bp_found = true;
            } 
            // The case for bp_iter_curr for 0xcc is less likely, standard is RIP is after 0xcc.
            // else if (bp_iter_curr != breakpoints_by_addr.end() && bp_iter_curr->second.is_enabled) {
            //     actual_bp_addr = regs_cache.rip; bp_found = true;
            // }

            if (bp_found) {
                if (in_syscall_execution_mode) { // Breakpoint hit during a PTRACE_SYSCALL command
                    in_syscall_execution_mode = false; // Breakpoint takes precedence
                    is_next_syscall_stop_entry = true; // Reset for next 'syscall' command
                }
                std::cout << "** hit a breakpoint at 0x" << std::hex << actual_bp_addr << "." << std::endl;
                regs_cache.rip = actual_bp_addr; 
                set_current_registers(); // Set child's RIP to the BP instruction
            } else { // SIGTRAP not from our BP (e.g., from PTRACE_SINGLESTEP)
                if (in_syscall_execution_mode) { // Unexpected trap during syscall mode
                     in_syscall_execution_mode = false;
                     is_next_syscall_stop_entry = true;
                }
            }
            return true;
        } else { // Other signal
            if(in_syscall_execution_mode) {
                in_syscall_execution_mode = false; // Any other signal also breaks syscall mode
                is_next_syscall_stop_entry = true;
            }
            return true;
        }
    }
    return false;
}

bool enable_bp_at_addr(uint64_t addr) { /* ... same ... */
    auto it = breakpoints_by_addr.find(addr);
    if (it == breakpoints_by_addr.end()) return false;
    if (it->second.is_enabled) return true;
    long orig_byte = read_memory_byte_internal(child_pid, addr);
    if (orig_byte == -1) return false;
    it->second.original_byte = static_cast<uint8_t>(orig_byte);
    if (!write_memory_byte_internal(child_pid, addr, 0xCC)) return false;
    it->second.is_enabled = true;
    return true;
}
bool disable_bp_at_addr(uint64_t addr) { /* ... same ... */
    auto it = breakpoints_by_addr.find(addr);
    if (it == breakpoints_by_addr.end() || !it->second.is_enabled) return true;
    if (!write_memory_byte_internal(child_pid, addr, it->second.original_byte)) { }
    it->second.is_enabled = false;
    return true;
}
bool step_over_instruction_at_breakpoint() { /* ... same, ensure get_current_registers is called after waitpid ... */
    if (!program_loaded || !regs_cache_valid) return false;
    auto bp_it = breakpoints_by_addr.find(regs_cache.rip);
    if (bp_it != breakpoints_by_addr.end() && bp_it->second.is_enabled) {
        disable_bp_at_addr(regs_cache.rip);
        ptrace_single_step(child_pid);
        int status;
        if (waitpid(child_pid, &status, 0) == -1) {
            enable_bp_at_addr(regs_cache.rip); program_loaded = false; child_pid = 0; return false;
        }
        get_current_registers(); // Crucial: update regs_cache after step
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            wait_for_process_event(status); return false;
        }
        enable_bp_at_addr(bp_it->first);
        return true;
    }
    return false;
}

uint64_t get_elf_entry_offset_from_readelf(const std::string& path) { /* ... same ... */
    std::string command = "readelf -h " + path + " 2>/dev/null | grep 'Entry point address:'";
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) return 0;
    char buffer[256]; std::string result_str; 
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) result_str += buffer;
    pclose(pipe);
    size_t pos = result_str.find("0x");
    if (pos != std::string::npos) {
        try { return std::stoull(result_str.substr(pos), nullptr, 16); } catch(...) { return 0; }
    }
    return 0;
}
bool check_elf_is_dynamic_from_readelf(const std::string& path) { /* ... same ... */
    std::string command = "readelf -h " + path + " 2>/dev/null | grep 'Type:'";
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) return false;
    char buffer[256]; std::string result_str; 
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) result_str += buffer;
    pclose(pipe);
    return result_str.find("DYN") != std::string::npos;
}

void handle_load_cmd(const std::vector<std::string>& args) { /* ... same, ensure program_actual_entry_point is set correctly ... */
    if (args.empty()) return;
    if (program_loaded && child_pid != 0) { /* ... cleanup ... */
        kill(child_pid, SIGKILL); waitpid(child_pid, nullptr, 0);
        child_pid = 0; program_loaded = false; breakpoints_by_addr.clear();
        breakpoint_addr_by_id.clear(); next_breakpoint_id = 0; executable_segments_global.clear();
        program_base_address = 0; program_actual_entry_point = 0; regs_cache_valid = false;
    }
    std::string current_program_path = args[0];
    if (access(current_program_path.c_str(), X_OK) == -1) { std::cout << "** program '" << current_program_path << "' not found or not executable." << std::endl; return; }
    child_pid = fork();
    if (child_pid == 0) { ptrace(PTRACE_TRACEME, 0, nullptr, nullptr); execl(current_program_path.c_str(), current_program_path.c_str(), (char*)nullptr); exit(1); }
    else if (child_pid > 0) {
        int status; waitpid(child_pid, &status, 0);
        if (WIFEXITED(status) || WIFSIGNALED(status)) { std::cout << "** program '" << current_program_path << "' failed to start." << std::endl; child_pid = 0; return; }
        ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL);
        program_loaded = true;
        update_executable_info_and_load_addr(child_pid, current_program_path);
        get_current_registers(); // Initial RIP
        uint64_t elf_file_entry_offset = get_elf_entry_offset_from_readelf(current_program_path);
        bool is_dynamic = check_elf_is_dynamic_from_readelf(current_program_path);

        if (is_dynamic) {
            if (program_base_address != 0 && elf_file_entry_offset != 0) {
                uint64_t target_entry = program_base_address + elf_file_entry_offset;
                program_actual_entry_point = target_entry; // Tentative
                if (regs_cache.rip != target_entry) {
                    long orig_byte = read_memory_byte_internal(child_pid, target_entry);
                    if (orig_byte != -1) {
                        write_memory_byte_internal(child_pid, target_entry, 0xCC);
                        ptrace_continue_execution(child_pid); waitpid(child_pid, &status, 0);
                        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
                            get_current_registers();
                            if (regs_cache.rip - 1 == target_entry) { regs_cache.rip = target_entry; set_current_registers(); }
                            program_actual_entry_point = regs_cache.rip; // Update with actual stop
                        } else { wait_for_process_event(status); return; }
                        write_memory_byte_internal(child_pid, target_entry, static_cast<uint8_t>(orig_byte));
                    } else { program_actual_entry_point = regs_cache.rip; }
                } else { program_actual_entry_point = regs_cache.rip; }
            } else { program_actual_entry_point = regs_cache.rip; }
        } else { // Static
            program_actual_entry_point = regs_cache.rip; // Trust initial stop for static
        }
        std::cout << "** program '" << current_program_path << "' loaded. entry point: 0x" << std::hex << program_actual_entry_point << "." << std::endl;
        disassemble_and_print(regs_cache.rip, 5);
    }
}

void execute_and_report(const std::string& cmd_type, const std::function<void(pid_t)>& ptrace_action) {
    if (!program_loaded) { std::cout << "** please load a program first." << std::endl; return; }

    // Manage syscall mode state based on the command
    if (cmd_type == "syscall") {
        if (!in_syscall_execution_mode) { // If user types 'syscall' and we are not already in a syscall pair
            is_next_syscall_stop_entry = true; // Expect syscall entry next
        }
        in_syscall_execution_mode = true; // This command instance will use PTRACE_SYSCALL
                                          // is_next_syscall_stop_entry will be toggled by wait_for_process_event
    } else {
        // Any other command (si, cont) should terminate a pending PTRACE_SYSCALL sequence
        if (in_syscall_execution_mode) {
            in_syscall_execution_mode = false;
            is_next_syscall_stop_entry = true; // Reset for any future 'syscall' command
        }
    }

    bool stepped_over_bp = false;
    if (regs_cache_valid) { 
        auto bp_it = breakpoints_by_addr.find(regs_cache.rip);
        if (bp_it != breakpoints_by_addr.end() && bp_it->second.is_enabled) {
            if (step_over_instruction_at_breakpoint()) { 
                stepped_over_bp = true;
                if (cmd_type == "si") { 
                    if (program_loaded) disassemble_and_print(regs_cache.rip, 5);
                    return;
                }
            } else { return; }
        }
    }
    
    ptrace_action(child_pid);
    int status;
    if (wait_for_process_event(status)) { 
        if (program_loaded) { 
            // regs_cache.rip might have been adjusted by wait_for_process_event for syscall display
            disassemble_and_print(regs_cache.rip, 5);
        }
    }
}
void handle_si_cmd() { execute_and_report("si", ptrace_single_step); }
void handle_cont_cmd() { execute_and_report("cont", ptrace_continue_execution); }
void handle_syscall_cmd_wrapper() { execute_and_report("syscall", ptrace_syscall_step); }

void handle_info_cmd(const std::vector<std::string>& args) {
    if (!program_loaded) { std::cout << "** please load a program first." << std::endl; return; }
    if (args.empty()) return;
    if (args[0] == "reg") {
        if (!get_current_registers()) { std::cerr << "Failed to get registers for info reg." << std::endl; return; }
        std::cout << "$rip  0x" << std::hex << std::setfill('0') << std::setw(16) << regs_cache.rip << std::endl; // Test direct print
        std::cout << "$rax  0x" << std::hex << std::setfill('0') << std::setw(16) << regs_cache.rax << std::endl; // Test direct print

        const char* names[] = {"$rax","$rbx","$rcx","$rdx","$rsi","$rdi","$rbp","$rsp","$r8","$r9","$r10","$r11","$r12","$r13","$r14","$r15","$rip","$eflags"};
        uint64_t vals_arr[] = {regs_cache.rax, regs_cache.rbx, regs_cache.rcx, regs_cache.rdx, regs_cache.rsi, regs_cache.rdi, regs_cache.rbp, regs_cache.rsp, regs_cache.r8, regs_cache.r9, regs_cache.r10, regs_cache.r11, regs_cache.r12, regs_cache.r13, regs_cache.r14, regs_cache.r15, regs_cache.rip, regs_cache.eflags};
        for (int i=0; i < 18; ++i) {
            std::cout << std::left << std::setw(5) << names[i] << " 0x";
            std::cout << std::hex << std::setfill('0') << std::setw(16) << vals_arr[i];
            std::cout << std::setfill(' ');
            if ((i+1)%3==0 || i==17) std::cout << std::endl; else std::cout << "    ";
        }
    } else if (args[0] == "break") { /* ... same ... */
        if (breakpoint_addr_by_id.empty()) { std::cout << "** no breakpoints." << std::endl; }
        else {
            std::cout << "Num     Address" << std::endl;
            std::vector<std::pair<int, uint64_t>> sorted_bps_by_id;
            for(const auto& pair : breakpoint_addr_by_id) { if (breakpoints_by_addr.count(pair.second)) { sorted_bps_by_id.push_back(pair); } }
            std::sort(sorted_bps_by_id.begin(), sorted_bps_by_id.end());
            for (const auto& pair : sorted_bps_by_id) { std::cout << std::left << std::setw(8) << pair.first << "0x" << std::hex << pair.second << std::endl; }
        }
    }
}

void add_new_breakpoint(uint64_t effective_addr) { /* ... same, remove debug prints if confident ... */
    // std::cerr << "[DEBUG] add_new_breakpoint: checking effective_addr = 0x" << std::hex << effective_addr << std::dec << std::endl;
    if (!is_address_in_executable_region(effective_addr)) {
        // std::cerr << "[DEBUG] add_new_breakpoint: effective_addr 0x" << std::hex << effective_addr << " is NOT in executable region." << std::dec << std::endl;
        std::cout << "** the target address is not valid." << std::endl; return;
    }
    // std::cerr << "[DEBUG] add_new_breakpoint: effective_addr 0x" << std::hex << effective_addr << " IS in executable region." << std::dec << std::endl;
    Breakpoint bp_new; bp_new.id = next_breakpoint_id++; bp_new.address = effective_addr; bp_new.is_enabled = false;
    breakpoints_by_addr[effective_addr] = bp_new; breakpoint_addr_by_id[bp_new.id] = effective_addr;
    if (!enable_bp_at_addr(effective_addr)) {
        std::cout << "** the target address is not valid." << std::endl;
        breakpoints_by_addr.erase(effective_addr); breakpoint_addr_by_id.erase(bp_new.id); next_breakpoint_id--; return;
    }
    std::cout << "** set a breakpoint at 0x" << std::hex << effective_addr << "." << std::endl;
}
void handle_break_cmd(const std::vector<std::string>& args) { /* ... same, ensure stoull base 16 ... */
    if (!program_loaded) { std::cout << "** please load a program first." << std::endl; return; }
    if (args.empty()) return; uint64_t addr;
    try { addr = std::stoull(args[0], nullptr, 16); } catch (...) { std::cout << "** the target address is not valid." << std::endl; return; }
    add_new_breakpoint(addr);
}
void handle_breakrva_cmd(const std::vector<std::string>& args) { /* ... same, ensure stoull base 16 ... */
    if (!program_loaded) { std::cout << "** please load a program first." << std::endl; return; }
    if (args.empty()) return; uint64_t offset;
    try { offset = std::stoull(args[0], nullptr, 16); } catch (...) { std::cout << "** the target address is not valid." << std::endl; return; }
    // std::cerr << "[DEBUG] handle_breakrva_cmd: offset = 0x" << std::hex << offset << std::dec << std::endl;
    // std::cerr << "[DEBUG] handle_breakrva_cmd: program_base_address = 0x" << std::hex << program_base_address << std::dec << std::endl;
    if (program_base_address == 0) { std::cout << "** the target address is not valid. (Base address not determined)" << std::endl; return; }
    uint64_t effective_addr = program_base_address + offset;
    // std::cerr << "[DEBUG] handle_breakrva_cmd: effective_addr for breakpoint = 0x" << std::hex << effective_addr << std::dec << std::endl;
    add_new_breakpoint(effective_addr);
}
void handle_delete_cmd(const std::vector<std::string>& args) { /* ... same ... */
    if (!program_loaded) { std::cout << "** please load a program first." << std::endl; return; }
    if (args.empty()) return; int id_del;
    try { id_del = std::stoi(args[0]); } catch (...) { std::cout << "** breakpoint " << args[0] << " does not exist." << std::endl; return; }
    auto id_map_it = breakpoint_addr_by_id.find(id_del);
    if (id_map_it == breakpoint_addr_by_id.end()) { std::cout << "** breakpoint " << id_del << " does not exist." << std::endl; return; }
    uint64_t addr_bp = id_map_it->second;
    if (breakpoints_by_addr.count(addr_bp) && breakpoints_by_addr[addr_bp].id == id_del) {
        disable_bp_at_addr(addr_bp); breakpoints_by_addr.erase(addr_bp);
    }
    breakpoint_addr_by_id.erase(id_map_it);
    std::cout << "** delete breakpoint " << id_del << "." << std::endl;
}
void handle_patch_cmd(const std::vector<std::string>& args) { /* ... same, ensure stoull base 16 for addr ... */
    if (!program_loaded) { std::cout << "** please load a program first." << std::endl; return; }
    if (args.size() < 2) return; uint64_t addr_patch;
    try { addr_patch = std::stoull(args[0], nullptr, 16); } catch (...) { std::cout << "** the target address is not valid." << std::endl; return; }
    const std::string& hex_val_str = args[1];
    if (hex_val_str.empty()||hex_val_str.length()%2!=0||hex_val_str.length()>2048){std::cout<<"** the target address is not valid."<<std::endl;return;}
    std::vector<uint8_t> bytes_patch_vec;
    for(size_t i=0;i<hex_val_str.length();i+=2){try{bytes_patch_vec.push_back(static_cast<uint8_t>(std::stoull(hex_val_str.substr(i,2),nullptr,16)));}catch(...){std::cout<<"** the target address is not valid."<<std::endl;return;}}
    for(size_t i=0;i<bytes_patch_vec.size();++i){if(!is_address_in_executable_region(addr_patch+i)){std::cout<<"** the target address is not valid."<<std::endl;return;}}
    for(size_t i=0;i<bytes_patch_vec.size();++i){
        uint64_t cb_addr = addr_patch+i; auto bp_it = breakpoints_by_addr.find(cb_addr);
        bool bp_enabled = false; uint8_t orig_byte_if_bp = 0;
        if(bp_it!=breakpoints_by_addr.end()&&bp_it->second.is_enabled){bp_enabled=true;orig_byte_if_bp=bp_it->second.original_byte;disable_bp_at_addr(cb_addr);}
        if(!write_memory_byte_internal(child_pid,cb_addr,bytes_patch_vec[i])){std::cout<<"** the target address is not valid."<<std::endl;if(bp_enabled){write_memory_byte_internal(child_pid,cb_addr,orig_byte_if_bp);enable_bp_at_addr(cb_addr);}return;}
        if(bp_enabled){bp_it->second.original_byte=bytes_patch_vec[i];if(!write_memory_byte_internal(child_pid,cb_addr,0xCC)){bp_it->second.is_enabled=false;}else{bp_it->second.is_enabled=true;}}
    }
    std::cout << "** patched memory at 0x" << std::hex << addr_patch << "." << std::endl;
}

void sdb_initialize() { /* ... same ... */ if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_handle_global) != CS_ERR_OK) { std::cerr << "FATAL: Capstone initialization failed." << std::endl; exit(1); } }
void sdb_cleanup() { /* ... same ... */ if (capstone_handle_global != 0) cs_close(&capstone_handle_global); if (child_pid != 0 && program_loaded) { kill(child_pid, SIGKILL); waitpid(child_pid, nullptr, 0); } }
std::vector<std::string> tokenize_input_line(const std::string& line) { /* ... same ... */ std::vector<std::string> t; std::string tk; std::istringstream s(line); while(s>>tk)t.push_back(tk); return t; }

int main(int argc, char* argv[]) {
    sdb_initialize(); std::atexit(sdb_cleanup);
    if (argc > 1) { handle_load_cmd({argv[1]}); }
    std::string line_input;
    while (true) {
        std::cout << PROMPT << std::flush;
        if (!std::getline(std::cin, line_input)) break;
        if (line_input.empty()) continue;
        auto tokens = tokenize_input_line(line_input);
        if (tokens.empty()) continue;
        const std::string& cmd = tokens[0];
        std::vector<std::string> cmd_args(tokens.begin() + 1, tokens.end());
        // ... command dispatch ...
        if (cmd == "load") handle_load_cmd(cmd_args);
        else if (cmd == "si") handle_si_cmd();
        else if (cmd == "cont") handle_cont_cmd();
        else if (cmd == "info") handle_info_cmd(cmd_args);
        else if (cmd == "break") handle_break_cmd(cmd_args);
        else if (cmd == "breakrva") handle_breakrva_cmd(cmd_args);
        else if (cmd == "delete") handle_delete_cmd(cmd_args);
        else if (cmd == "patch") handle_patch_cmd(cmd_args);
        else if (cmd == "syscall") handle_syscall_cmd_wrapper();
        else if (cmd == "exit" || cmd == "quit" || cmd == "q") break;
        else {
            if (!program_loaded && cmd != "load") { std::cout << "** please load a program first." << std::endl; }
            else { std::cout << "** Unknown command: " << cmd << std::endl; }
        }
    }
    return 0;
}