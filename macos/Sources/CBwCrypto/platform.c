#include "include/CBwCrypto.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <stdlib.h>
#include <string.h>
void bw_wipe(void *p, size_t n) { volatile unsigned char *v = p; while (n--) *v++ = 0; }
int bw_peer_pid(int fd) {
    pid_t pid = -1; socklen_t n = sizeof(pid);
    return getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &n) == 0 ? pid : -1;
}
int bw_process(int pid, int *parent, uint64_t *started, char *path, size_t size) {
    struct proc_bsdinfo info;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info)) return -1;
    *parent = info.pbi_ppid;
    *started = info.pbi_start_tvsec * 1000000 + info.pbi_start_tvusec;
    return proc_pidpath(pid, path, (uint32_t)size) > 0 ? 0 : -1;
}
int bw_arguments(int pid, char *output, size_t size) {
    int mib[] = { CTL_KERN, KERN_PROCARGS2, pid }; size_t n = 0;
    if (sysctl(mib, 3, NULL, &n, NULL, 0) != 0 || n < sizeof(int) || n > 4 * 1024 * 1024) return -1;
    char *buffer = calloc(n, 1); if (!buffer) return -1;
    if (sysctl(mib, 3, buffer, &n, NULL, 0) != 0) { free(buffer); return -1; }
    int argc; memcpy(&argc, buffer, sizeof(argc)); size_t p = sizeof(argc), used = 0;
    while (p < n && buffer[p]) p++;
    while (p < n && !buffer[p]) p++;
    for (int i = 0; i < argc && p < n; i++) {
        size_t len = strnlen(buffer + p, n - p);
        if (p + len >= n || used + len + 1 > size) break;
        memcpy(output + used, buffer + p, len + 1); used += len + 1; p += len + 1;
    }
    bw_wipe(buffer, n); free(buffer); return (int)used;
}
