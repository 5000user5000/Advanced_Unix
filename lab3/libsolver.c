#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include "libgotoku.h"

// 前置宣告
void gop_hook(void);
void do_nothing(void);

// =========================================================================
// 印出挑戰字串與 main 地址
// =========================================================================
__attribute__((constructor))
static void init_solver() {
    fprintf(stderr, "UP113_GOT_PUZZLE_CHALLENGE\n");
}

int game_init() {
    int (*orig_game_init)() = dlsym(RTLD_NEXT, "game_init");
    int ret = orig_game_init();
    void *main_addr = game_get_ptr();
    fprintf(stderr, "SOLVER: _main = %p\n", main_addr);
    return ret;
}

// =========================================================================
// Sudoku 求解（與 Part A 相同）
// =========================================================================
int is_valid(int board[9][9], int row, int col, int num) {
    for (int c = 0; c < 9; c++) {
        if (board[row][c] == num)
            return 0;
    }
    for (int r = 0; r < 9; r++) {
        if (board[r][col] == num)
            return 0;
    }
    int sr = (row / 3) * 3, sc = (col / 3) * 3;
    for (int r = 0; r < 3; r++)
        for (int c = 0; c < 3; c++)
            if (board[sr + r][sc + c] == num)
                return 0;
    return 1;
}

int sudoku_solve(int board[9][9]) {
    for (int row = 0; row < 9; row++) {
        for (int col = 0; col < 9; col++) {
            if (board[row][col] == 0) {
                for (int num = 1; num <= 9; num++) {
                    if (is_valid(board, row, col, num)) {
                        board[row][col] = num;
                        if (sudoku_solve(board))
                            return 1;
                        board[row][col] = 0;
                    }
                }
                return 0;
            }
        }
    }
    return 1;
}

// =========================================================================
// 計算最短移動差值（環狀走法，範圍約 -4 ~ 4）
// =========================================================================
int mod_diff(int current, int target) {
    int diff = target - current;
    if (diff > 4)
        diff -= 9;
    if (diff < -4)
        diff += 9;
    return diff;
}

// =========================================================================
// 操作序列：記錄每一步呼叫哪個 gop_* 函數
// =========================================================================
typedef void (*op_func_t)(void);
#define MAX_OPS 2000
static op_func_t op_seq[MAX_OPS];
static int op_seq_len = 0;
static int op_index = 0;

void record_op(op_func_t op) {
    if (op_seq_len < MAX_OPS)
        op_seq[op_seq_len++] = op;
}

// =========================================================================
// 宣告外部 gop_* 函數（由 libgotoku.so 提供）
// =========================================================================
extern void gop_up();
extern void gop_down();
extern void gop_left();
extern void gop_right();
extern void gop_fill_1();
extern void gop_fill_2();
extern void gop_fill_3();
extern void gop_fill_4();
extern void gop_fill_5();
extern void gop_fill_6();
extern void gop_fill_7();
extern void gop_fill_8();
extern void gop_fill_9();

// =========================================================================
// 建立從當前光標移動到 (target_row, target_col) 並填入 fill_num 的操作序列
// =========================================================================
void build_op_sequence(gotoku_t *gt, int target_row, int target_col, int fill_num) {
    int cur_row = gt->y, cur_col = gt->x;
    int dr = mod_diff(cur_row, target_row);
    int dc = mod_diff(cur_col, target_col);
    if (dr > 0) {
        for (int i = 0; i < dr; i++)
            record_op(gop_down);
    } else if (dr < 0) {
        for (int i = 0; i < -dr; i++)
            record_op(gop_up);
    }
    if (dc > 0) {
        for (int i = 0; i < dc; i++)
            record_op(gop_right);
    } else if (dc < 0) {
        for (int i = 0; i < -dc; i++)
            record_op(gop_left);
    }
    // 記錄填數操作
    switch (fill_num) {
        case 1: record_op(gop_fill_1); break;
        case 2: record_op(gop_fill_2); break;
        case 3: record_op(gop_fill_3); break;
        case 4: record_op(gop_fill_4); break;
        case 5: record_op(gop_fill_5); break;
        case 6: record_op(gop_fill_6); break;
        case 7: record_op(gop_fill_7); break;
        case 8: record_op(gop_fill_8); break;
        case 9: record_op(gop_fill_9); break;
        default: break;
    }
    // 更新光標位置
    gt->x = target_col;
    gt->y = target_row;
}

// 依原始棋盤與解答建立完整操作序列（只針對原本為 0 的格子）
void build_full_sequence(gotoku_t *gt, int original[9][9], int solved[9][9]) {
    for (int row = 0; row < 9; row++){
        for (int col = 0; col < 9; col++){
            if (original[row][col] == 0) {
                build_op_sequence(gt, row, col, solved[row][col]);
            }
        }
    }
    fprintf(stderr, "Total op_seq length: %d\n", op_seq_len);
}

// =========================================================================
// GOT hooking 部分
// =========================================================================

// 定義結構，記錄每個 GOT entry 的相對偏移
struct got_entry {
    const char *name;
    unsigned long offset;  // 此數值為相對於 main 的偏移，請根據 pwntools 結果調整
};

//【示意】以下列出 gop_1～gop_5 的偏移，實際上你必須補齊所有被呼叫的 gop_* 函數
struct got_entry got_entries[] = {
    {"gop_1", 0x231b0},
    {"gop_2", 0x21ea8},
    {"gop_3", 0x22000},  // 示意值
    {"gop_4", 0x22050},  // 示意值
    {"gop_5", 0x220A0}   // 示意值
};
#define NUM_GOT_ENTRIES (sizeof(got_entries)/sizeof(got_entries[0]))

// 保存原始 GOT 值（這裡我們不一定用到，因後續我們改為設為 do_nothing）
static unsigned long orig_got_values[NUM_GOT_ENTRIES];

// 修改 GOT 表：將所有目標 gop_* 的入口修改為我們的 hook 函數
void modify_got_table(void *main_addr) {
    int page_size = sysconf(_SC_PAGE_SIZE);
    // rel_main 為 main 函數在 gotoku 執行檔中的相對偏移（示意值，請依實際結果調整）
    unsigned long rel_main = 0x1b7a9;
    for (int i = 0; i < NUM_GOT_ENTRIES; i++) {
        unsigned long got_entry_addr = (unsigned long)main_addr - rel_main + got_entries[i].offset;
        unsigned long page_start = got_entry_addr & ~(page_size - 1);
        if (mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) < 0) {
            perror("mprotect");
            exit(1);
        }
        unsigned long *ptr = (unsigned long*)got_entry_addr;
        orig_got_values[i] = *ptr;
        *ptr = (unsigned long)gop_hook;
    }
    fprintf(stderr, "GOT table modified.\n");
}

// 設定 GOT 表所有目標入口為 do_nothing（以便屏蔽後續呼叫）
void set_got_to_donothing(void *main_addr) {
    int page_size = sysconf(_SC_PAGE_SIZE);
    unsigned long rel_main = 0x1b7a9;
    for (int i = 0; i < NUM_GOT_ENTRIES; i++) {
        unsigned long got_entry_addr = (unsigned long)main_addr - rel_main + got_entries[i].offset;
        unsigned long page_start = got_entry_addr & ~(page_size - 1);
        if (mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) < 0) {
            perror("mprotect set do_nothing");
            exit(1);
        }
        *((unsigned long*)got_entry_addr) = (unsigned long)do_nothing;
    }
    fprintf(stderr, "GOT table set to do_nothing.\n");
}

// =========================================================================
// Hook 函數：所有被劫持的 gop_* 呼叫都轉而執行此函數
// =========================================================================
void gop_hook(void) {
    if (op_index < op_seq_len) {
        op_seq[op_index++]();
    }
}

// =========================================================================
// 定義一個空函數，用於後續屏蔽隨機調用
// =========================================================================
void do_nothing(void) {
    // 完全空實作
}

// =========================================================================
// 重載 game_load：讀取棋盤、求解 sudoku、建立操作序列，然後執行操作序列，並修改 GOT 表
// =========================================================================
gotoku_t* game_load(const char *path) {
    gotoku_t* (*orig_game_load)(const char*) = dlsym(RTLD_NEXT, "game_load");
    gotoku_t *gt = orig_game_load(path);
    if (!gt)
        return NULL;
    int original[9][9], solved[9][9];
    for (int i = 0; i < 9; i++){
        for (int j = 0; j < 9; j++){
            original[i][j] = gt->board[i][j];
            solved[i][j] = gt->board[i][j];
        }
    }
    if (!sudoku_solve(solved)) {
        fprintf(stderr, "Solver: Failed to solve sudoku!\n");
        return gt;
    }
    fprintf(stderr, "Solved board:\n");
    for (int i = 0; i < 9; i++){
        for (int j = 0; j < 9; j++){
            fprintf(stderr, "%d ", solved[i][j]);
        }
        fprintf(stderr, "\n");
    }
    op_seq_len = 0;
    op_index = 0;
    build_full_sequence(gt, original, solved);
    void *main_addr = game_get_ptr();
    // 修改 GOT 表，將所有 gop_* 入口劫持至 gop_hook
    modify_got_table(main_addr);
    // 立即執行操作序列
    while (op_index < op_seq_len) {
        gop_hook();
    }
    // 執行完畢後，將 GOT 表設為 do_nothing，以屏蔽後續調用
    set_got_to_donothing(main_addr);
    return gt;
}

// =========================================================================
// 覆寫 gop_random 以防止後續隨機操作干擾
// =========================================================================
void gop_random() {
    // 空實作
}
