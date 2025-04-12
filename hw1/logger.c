#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netdb.h>
#include <sys/un.h>

typedef long (*syscall_hook_fn_t)(long, long, long, long, long, long, long);
static syscall_hook_fn_t real_syscall = NULL;

static void escape_and_print_buffer(const char *prefix, int fd, const char *buf, size_t count, long ret) {
    char out[512] = {0};
    size_t len = (ret > 32 ? 32 : ret);
    int j = 0;

    for (size_t i = 0; i < len && j < sizeof(out) - 5; i++) {
        unsigned char c = buf[i];
        if (c == '\n') {
            out[j++] = '\\'; out[j++] = 'n';
        } else if (c == '\t') {
            out[j++] = '\\'; out[j++] = 't';
        } else if (c == '\r') {
            out[j++] = '\\'; out[j++] = 'r';
        } else if (c >= 32 && c < 127) {
            out[j++] = c;
        } else {
            j += snprintf(out + j, 5, "\\x%02x", c);
        }
    }

    if (ret > 32) strcat(out, "...");
    fprintf(stderr, "[logger] %s(%d, \"%s\", %ld) = %ld\n", prefix, fd, out, count, ret);
}

static long logger_syscall_hook(long syscall_num,
                                long rdi, long rsi, long rdx,
                                long r10, long r8, long r9) {
    // openat
    if (syscall_num == 257) {
        const char *pathname = (const char *)rsi;
        int dirfd = (int)rdi;
        int flags = (int)rdx;
        mode_t mode = (mode_t)r10;

        long ret = real_syscall(syscall_num, rdi, rsi, rdx, r10, r8, r9);
        fprintf(stderr, "[logger] openat(%s, \"%s\", 0x%x, %#o) = %ld\n",
                dirfd == -100 ? "AT_FDCWD" : "FD", pathname, flags, mode, ret);
        return ret;
    }

    // read
    if (syscall_num == 0) {
        int fd = rdi;
        const char *buf = (const char *)rsi;
        size_t count = (size_t)rdx;

        long ret = real_syscall(syscall_num, rdi, rsi, rdx, r10, r8, r9);
        escape_and_print_buffer("read", fd, buf, count, ret);
        return ret;
    }

    // write
    if (syscall_num == 1) {
        int fd = rdi;
        const char *buf = (const char *)rsi;
        size_t count = (size_t)rdx;

        long ret = real_syscall(syscall_num, rdi, rsi, rdx, r10, r8, r9);
        escape_and_print_buffer("write", fd, buf, count, ret);
        return ret;
    }

    // connect
    if (syscall_num == 42) {
        int fd = rdi;
        struct sockaddr *addr = (struct sockaddr *)rsi;
        socklen_t addrlen = rdx;
        char ipbuf[256] = "-";

        if (addr->sa_family == AF_INET) {
            struct sockaddr_in *in = (struct sockaddr_in *)addr;
            inet_ntop(AF_INET, &in->sin_addr, ipbuf, sizeof(ipbuf));
            snprintf(ipbuf + strlen(ipbuf), sizeof(ipbuf) - strlen(ipbuf), ":%d", ntohs(in->sin_port));
        } else if (addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;
            inet_ntop(AF_INET6, &in6->sin6_addr, ipbuf, sizeof(ipbuf));
            snprintf(ipbuf + strlen(ipbuf), sizeof(ipbuf) - strlen(ipbuf), ":%d", ntohs(in6->sin6_port));
        } else if (addr->sa_family == AF_UNIX) {
            struct sockaddr_un *sun = (struct sockaddr_un *)addr;
            snprintf(ipbuf, sizeof(ipbuf), "UNIX:%s", sun->sun_path);
        }

        long ret = real_syscall(syscall_num, rdi, rsi, rdx, r10, r8, r9);
        fprintf(stderr, "[logger] connect(%d, \"%s\", %d) = %ld\n", fd, ipbuf, addrlen, ret);
        return ret;
    }

    // execve
    if (syscall_num == 59) {
        const char *filename = (const char *)rdi;
        void *argv_ptr = (void *)rsi;
        void *envp_ptr = (void *)rdx;

        fprintf(stderr, "[logger] execve(\"%s\", %p, %p)\n", filename, argv_ptr, envp_ptr);
        return real_syscall(syscall_num, rdi, rsi, rdx, r10, r8, r9);
    }

    return real_syscall(syscall_num, rdi, rsi, rdx, r10, r8, r9);
}

// 標準 hook 初始化介面
int __hook_init(long unused, syscall_hook_fn_t *hooked_syscall) {
    fprintf(stderr, "[logger] __hook_init called\n");

    real_syscall = *hooked_syscall;
    *hooked_syscall = logger_syscall_hook;

    return 0;
}
