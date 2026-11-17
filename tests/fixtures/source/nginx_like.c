#include <stddef.h>

extern long recv(int, void *, size_t, int);
extern int open(const char *, int);
extern long writev(int, const void *, int);
extern long sendfile(int, int, long *, size_t);

int serve_request(int fd) {
    char buf[1024];
    long n = recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) {
        return -1;
    }
    int file_fd = open("/srv/report.pdf", 0);
    if (file_fd < 0) {
        return -1;
    }
    writev(fd, 0, 0);
    sendfile(fd, file_fd, 0, 4096);
    return 0;
}
