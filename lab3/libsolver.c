#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include "libgotoku.h"

// 在共享庫載入時印出挑戰字串
__attribute__((constructor))
static void init_solver() {
    fprintf(stderr, "UP113_GOT_PUZZLE_CHALLENGE\n");
}

// 重載 game_init：呼叫原始 game_init 後，取得 main 函數地址並印出
int game_init() {
    int (*orig_game_init)() = dlsym(RTLD_NEXT, "game_init");
    int ret = orig_game_init();
    void *main_ptr = game_get_ptr();
    fprintf(stderr, "SOLVER: _main = %p\n", main_ptr);
    return ret;
}

// 判斷在 (row, col) 放入 num 是否合法
int is_valid(int board[9][9], int row, int col, int num) {
    for (int c = 0; c < 9; c++) {
        if (board[row][c] == num) return 0;
    }
    for (int r = 0; r < 9; r++) {
        if (board[r][col] == num) return 0;
    }
    int sr = (row / 3) * 3;
    int sc = (col / 3) * 3;
    for (int r = 0; r < 3; r++) {
        for (int c = 0; c < 3; c++) {
            if (board[sr + r][sc + c] == num) return 0;
        }
    }
    return 1;
}

// 標準回溯法求解 sudoku，成功回傳 1 並填滿 board，否則回傳 0
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

// 模擬從目前光標移動到目標位置並填入數字
// 這裡採用最簡單的方法：以 gop_down 及 gop_right 進行正向移動（利用 mod 9 會剛好回到對應位置）
void move_to_and_fill(gotoku_t *gt, int target_row, int target_col, int num) {
    int cur_row = gt->y;
    int cur_col = gt->x;
    // 計算正向移動步數（注意：由於 board 為環狀，(current + diff) % 9 == target）
    int dr = (target_row - cur_row + 9) % 9;
    int dc = (target_col - cur_col + 9) % 9;
    // 依序移動
    for (int i = 0; i < dr; i++) {
        void (*gop_down_func)() = dlsym(RTLD_NEXT, "gop_down");
        gop_down_func();
    }
    for (int i = 0; i < dc; i++) {
        void (*gop_right_func)() = dlsym(RTLD_NEXT, "gop_right");
        gop_right_func();
    }
    fprintf(stderr, "Filling cell (%d,%d) with %d; cursor now at (%d,%d)\n",
            target_row, target_col, num, gt->y, gt->x);
    // 根據數字呼叫對應的填數函數
    char func_name[20];
    sprintf(func_name, "gop_fill_%d", num);
    void (*fill_func)() = dlsym(RTLD_NEXT, func_name);
    fill_func();
}

// 模擬解題流程：對原本為空的格子依序移動並填入 sudoku 求解後的數字
void simulate_solution(gotoku_t *gt, int original[9][9], int solved[9][9]) {
    fprintf(stderr, "Solved board:\n");
    for (int i = 0; i < 9; i++) {
        for (int j = 0; j < 9; j++) {
            fprintf(stderr, "%d ", solved[i][j]);
        }
        fprintf(stderr, "\n");
    }
    // 依序掃描棋盤，對原始為 0 的格子執行移動與填數
    for (int row = 0; row < 9; row++) {
        for (int col = 0; col < 9; col++) {
            if (original[row][col] == 0) {
                move_to_and_fill(gt, row, col, solved[row][col]);
            }
        }
    }
}

// 重載 game_load：先呼叫原始 game_load 取得棋盤，再利用 sudoku_solve 求解後模擬移動填數
gotoku_t* game_load(const char *path) {
    gotoku_t* (*orig_game_load)(const char*) = dlsym(RTLD_NEXT, "game_load");
    gotoku_t *gt = orig_game_load(path);
    if (!gt)
        return NULL;

    int original[9][9], solved[9][9];
    for (int i = 0; i < 9; i++) {
        for (int j = 0; j < 9; j++) {
            original[i][j] = gt->board[i][j];
            solved[i][j] = gt->board[i][j];
        }
    }
    if (!sudoku_solve(solved)) {
        fprintf(stderr, "Solver: Failed to solve sudoku!\n");
        return gt;
    }
    simulate_solution(gt, original, solved);
    return gt;
}

// 為了避免 gotoku.c 後續呼叫 gop_* 時進行隨機移動，重載 gop_random 為空實作
void gop_random() {
    // 空實作，防止後續隨機操作影響已填入的解
}
