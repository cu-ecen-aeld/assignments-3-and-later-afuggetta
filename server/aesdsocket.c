#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#define LISTEN_PORT 9000
#define BACKLOG 10
#define DATAFILE "/var/tmp/aesdsocketdata"

static volatile sig_atomic_t exit_requested = 0;

static void signal_handler(int signo)
{
    (void)signo;
    exit_requested = 1;
    syslog(LOG_USER | LOG_INFO, "Caught signal, exiting");
}

static int install_signal_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    if (sigaction(SIGINT, &sa, NULL) == -1) return -1;
    if (sigaction(SIGTERM, &sa, NULL) == -1) return -1;
    return 0;
}

static int send_file_to_client(int client_fd)
{
    int fd = open(DATAFILE, O_RDONLY);
    if (fd == -1) {
        if (errno == ENOENT) return 0; // nothing to send yet
        syslog(LOG_USER | LOG_ERR, "open %s failed: %m", DATAFILE);
        return -1;
    }

    char buf[4096];
    ssize_t r;
    while ((r = read(fd, buf, sizeof(buf))) > 0) {
        size_t sent = 0;
        while (sent < (size_t)r) {
            ssize_t s = send(client_fd, buf + sent, (size_t)r - sent, 0);
            if (s < 0) {
                if (errno == EINTR) continue;
                syslog(LOG_USER | LOG_ERR, "send failed: %m");
                close(fd);
                return -1;
            }
            sent += (size_t)s;
        }
    }

    if (r < 0) syslog(LOG_USER | LOG_ERR, "read %s failed: %m", DATAFILE);

    close(fd);
    return (r < 0) ? -1 : 0;
}

static int daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0) {
        syslog(LOG_USER | LOG_ERR, "fork failed: %m");
        return -1;
    }
    if (pid > 0) _exit(0); // parent exits

    if (setsid() == -1) {
        syslog(LOG_USER | LOG_ERR, "setsid failed: %m");
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        syslog(LOG_USER | LOG_ERR, "second fork failed: %m");
        return -1;
    }
    if (pid > 0) _exit(0);

    umask(0);
    if (chdir("/") == -1) {
        syslog(LOG_USER | LOG_ERR, "chdir('/') failed: %m");
        return -1;
    }

    int fdnull = open("/dev/null", O_RDWR);
    if (fdnull >= 0) {
        dup2(fdnull, STDIN_FILENO);
        dup2(fdnull, STDOUT_FILENO);
        dup2(fdnull, STDERR_FILENO);
        if (fdnull > 2) close(fdnull);
    }

    closelog();
    openlog("aesdsocket", LOG_PID, LOG_USER);
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-d]\n", prog);
}

int main(int argc, char *argv[])
{
    bool run_as_daemon = false;
    if (argc == 2) {
        if (strcmp(argv[1], "-d") == 0) run_as_daemon = true;
        else { usage(argv[0]); return EXIT_FAILURE; }
    } else if (argc > 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    openlog("aesdsocket", LOG_PID, LOG_USER);

    if (install_signal_handlers() == -1) {
        syslog(LOG_USER | LOG_ERR, "sigaction failed: %m");
        closelog();
        return -1;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        syslog(LOG_USER | LOG_ERR, "socket failed: %m");
        closelog();
        return -1;
    }

    int yes = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
        syslog(LOG_USER | LOG_ERR, "setsockopt SO_REUSEADDR failed: %m");
        close(server_fd);
        closelog();
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(LISTEN_PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        syslog(LOG_USER | LOG_ERR, "bind failed: %m");
        close(server_fd);
        closelog();
        return -1;
    }

    if (run_as_daemon) {
        if (daemonize() == -1) {
            close(server_fd);
            closelog();
            return -1;
        }
    }

    if (listen(server_fd, BACKLOG) == -1) {
        syslog(LOG_USER | LOG_ERR, "listen failed: %m");
        close(server_fd);
        closelog();
        return -1;
    }

    // Make sure data file exists
    int df = open(DATAFILE, O_CREAT | O_APPEND, 0644);
    if (df != -1) close(df);

    while (!exit_requested) {
        struct sockaddr_storage client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd == -1) {
            if (errno == EINTR) {
                if (exit_requested) break; // interrupted by signal
                continue; // otherwise retry
            }
            syslog(LOG_USER | LOG_ERR, "accept failed: %m");
            continue;
        }

        char host[INET6_ADDRSTRLEN] = {0};
        void *addrptr = NULL;
        if (client_addr.ss_family == AF_INET) {
            addrptr = &((struct sockaddr_in *)&client_addr)->sin_addr;
        } else if (client_addr.ss_family == AF_INET6) {
            addrptr = &((struct sockaddr_in6 *)&client_addr)->sin6_addr;
        }
        if (addrptr && inet_ntop(client_addr.ss_family, addrptr, host, sizeof(host)))
            syslog(LOG_USER | LOG_INFO, "Accepted connection from %s", host);
        else
            syslog(LOG_USER | LOG_INFO, "Accepted connection from (unknown)");

        char recvbuf[1024];
        size_t packet_cap = 1024;
        size_t packet_len = 0;
        char *packet = malloc(packet_cap);
        if (!packet) {
            syslog(LOG_USER | LOG_ERR, "malloc failed");
            close(client_fd);
            continue;
        }

        bool client_open = true;
        while (client_open && !exit_requested) {
            ssize_t n = recv(client_fd, recvbuf, sizeof(recvbuf), 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                syslog(LOG_USER | LOG_ERR, "recv failed: %m");
                break;
            } else if (n == 0) {
                break; // client closed
            }

            if (packet_len + (size_t)n > packet_cap) {
                size_t new_cap = packet_cap * 2;
                while (new_cap < packet_len + (size_t)n) new_cap *= 2;
                char *tmp = realloc(packet, new_cap);
                if (!tmp) {
                    syslog(LOG_USER | LOG_ERR, "realloc failed");
                    free(packet);
                    packet_cap = 1024;
                    packet_len = 0;
                    packet = malloc(packet_cap);
                    if (!packet) { syslog(LOG_USER | LOG_ERR, "malloc failed"); break; }
                } else {
                    packet = tmp;
                    packet_cap = new_cap;
                }
            }

            memcpy(packet + packet_len, recvbuf, (size_t)n);
            packet_len += (size_t)n;

            size_t start = 0;
            for (size_t i = 0; i < packet_len; i++) {
                if (packet[i] == '\n') {
                    size_t line_len = i - start + 1; // include newline

                    int afd = open(DATAFILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
                    if (afd == -1) {
                        syslog(LOG_USER | LOG_ERR, "open %s for append failed: %m", DATAFILE);
                        client_open = false;
                        break;
                    }
                    ssize_t w = write(afd, packet + start, line_len);
                    if (w < 0 || (size_t)w != line_len) {
                        syslog(LOG_USER | LOG_ERR, "write to %s failed: %m", DATAFILE);
                        close(afd);
                        client_open = false;
                        break;
                    }
                    close(afd);

                    if (send_file_to_client(client_fd) == -1) {
                        client_open = false;
                        break;
                    }

                    start = i + 1;
                }
            }

            if (start > 0 && start < packet_len) {
                memmove(packet, packet + start, packet_len - start);
                packet_len -= start;
            } else if (start == packet_len) {
                packet_len = 0;
            }
        }

        free(packet);
        if (addrptr && inet_ntop(client_addr.ss_family, addrptr, host, sizeof(host)))
            syslog(LOG_USER | LOG_INFO, "Closed connection from %s", host);
        else
            syslog(LOG_USER | LOG_INFO, "Closed connection from (unknown)");

        close(client_fd);
    }

    close(server_fd);
    unlink(DATAFILE);
    closelog();

    return 0;
}
