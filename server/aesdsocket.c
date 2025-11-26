#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#ifndef USE_AESD_CHAR_DEVICE
#define USE_AESD_CHAR_DEVICE 1   /* default ON */
#endif

#define LISTEN_PORT 9000
#define BACKLOG 10
#if USE_AESD_CHAR_DEVICE
#define DATAFILE "/dev/aesdchar"
#else
#define DATAFILE "/var/tmp/aesdsocketdata"
#endif
static volatile sig_atomic_t exit_requested = 0;
static int server_fd = -1;

/* Mutex to protect all writes (and read+write sequences) to DATAFILE */
static pthread_mutex_t data_mutex = PTHREAD_MUTEX_INITIALIZER;

#if !USE_AESD_CHAR_DEVICE
// Thread for writing timestamp (only used when not using aesdchar)
/* Timer thread for periodic timestamp */
static pthread_t timer_thread;
#endif
/* Per-client thread tracking (singly linked list) */
struct client_thread {
    pthread_t thread_id;
    int client_fd;
    char client_ip[INET6_ADDRSTRLEN];
    volatile sig_atomic_t complete;  // set by thread when done
    struct client_thread *next;
};

static struct client_thread *thread_list_head = NULL;

/* Forward declarations */
static void *client_thread_func(void *arg);
static void *timestamp_thread_func(void *arg);

/* ========== Signal handling ========== */

static void signal_handler(int signo)
{
    (void)signo;
    exit_requested = 1;
    syslog(LOG_USER | LOG_INFO, "Caught signal, exiting");

    if (server_fd != -1) {
        /* Wake up accept() if blocked */
        shutdown(server_fd, SHUT_RDWR);
    }
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

/* ========== Thread list helpers ========== */

static void thread_list_add(struct client_thread *node)
{
    node->next = thread_list_head;
    thread_list_head = node;
}

/* Join and remove any threads that marked complete */
static void thread_list_cleanup_completed(void)
{
    struct client_thread *prev = NULL;
    struct client_thread *cur = thread_list_head;

    while (cur) {
        if (cur->complete) {
            pthread_join(cur->thread_id, NULL);

            struct client_thread *to_free = cur;
            if (prev) {
                prev->next = cur->next;
            } else {
                thread_list_head = cur->next;
            }
            cur = cur->next;
            free(to_free);
        } else {
            prev = cur;
            cur = cur->next;
        }
    }
}

/* Join and free all remaining threads on shutdown */
static void thread_list_join_all(void)
{
    struct client_thread *cur = thread_list_head;
    while (cur) {
        pthread_join(cur->thread_id, NULL);
        struct client_thread *to_free = cur;
        cur = cur->next;
        free(to_free);
    }
    thread_list_head = NULL;
}

/* ========== Data file helper (no locking here) ========== */

static int send_file_to_client_nolock(int client_fd)
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

#if !USE_AESD_CHAR_DEVICE
/* ========== Timer thread: append timestamp every 10s ========== */

static void *timestamp_thread_func(void *arg)
{
    (void)arg;

    while (!exit_requested) {
        /* Sleep in 1s chunks so we respond more quickly to exit */
        for (int i = 0; i < 10 && !exit_requested; i++) {
            sleep(1);
        }
        if (exit_requested) break;

        time_t now = time(NULL);
        struct tm t;
        if (!localtime_r(&now, &t)) {
            syslog(LOG_USER | LOG_ERR, "localtime_r failed: %m");
            continue;
        }

        /* RFC 2822-style format: "%a, %d %b %Y %T %z" */
        char timebuf[128];
        if (strftime(timebuf, sizeof(timebuf), "%a, %d %b %Y %T %z", &t) == 0) {
            syslog(LOG_USER | LOG_ERR, "strftime failed");
            continue;
        }

        char outbuf[256];
        int len = snprintf(outbuf, sizeof(outbuf), "timestamp:%s\n", timebuf);
        if (len < 0 || (size_t)len >= sizeof(outbuf)) {
            syslog(LOG_USER | LOG_ERR, "snprintf for timestamp failed");
            continue;
        }

        if (pthread_mutex_lock(&data_mutex) != 0) {
            syslog(LOG_USER | LOG_ERR, "pthread_mutex_lock failed in timer thread");
            continue;
        }

        int fd = open(DATAFILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd == -1) {
            syslog(LOG_USER | LOG_ERR, "open %s in timer thread failed: %m", DATAFILE);
            pthread_mutex_unlock(&data_mutex);
            continue;
        }

        ssize_t w = write(fd, outbuf, (size_t)len);
        if (w < 0 || w != len) {
            syslog(LOG_USER | LOG_ERR, "timestamp write failed: %m");
        }

        close(fd);
        pthread_mutex_unlock(&data_mutex);
    }

    return NULL;
}
#endif
/* ========== Daemonize ========== */

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

/* ========== Per-client thread function ========== */

static void *client_thread_func(void *arg)
{
    struct client_thread *info = (struct client_thread *)arg;
    int client_fd = info->client_fd;

    char recvbuf[1024];
    size_t packet_cap = 1024;
    size_t packet_len = 0;
    char *packet = malloc(packet_cap);
    if (!packet) {
        syslog(LOG_USER | LOG_ERR, "malloc failed in client thread");
        info->complete = 1;
        return NULL;
    }

    syslog(LOG_USER | LOG_INFO, "Handling connection from %s", info->client_ip);

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
                if (!packet) {
                    syslog(LOG_USER | LOG_ERR, "malloc failed");
                    break;
                }
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

                if (pthread_mutex_lock(&data_mutex) != 0) {
                    syslog(LOG_USER | LOG_ERR, "pthread_mutex_lock failed in client thread");
                    client_open = false;
                    break;
                }

#if !USE_AESD_CHAR_DEVICE
                int afd = open(DATAFILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
                if (afd == -1) {
                    syslog(LOG_USER | LOG_ERR, "open %s for append failed: %m", DATAFILE);
                    pthread_mutex_unlock(&data_mutex);
                    client_open = false;
                    break;
                }

                ssize_t w = write(afd, packet + start, line_len);
                if (w < 0 || (size_t)w != line_len) {
                    syslog(LOG_USER | LOG_ERR, "write to %s failed: %m", DATAFILE);
                    close(afd);
                    pthread_mutex_unlock(&data_mutex);
                    client_open = false;
                    break;
                }
                close(afd);
#endif
                if (send_file_to_client_nolock(client_fd) == -1) {
                    pthread_mutex_unlock(&data_mutex);
                    client_open = false;
                    break;
                }

                pthread_mutex_unlock(&data_mutex);

                start = i + 1;
            }
        }

        if (!client_open) break;

        if (start > 0 && start < packet_len) {
            memmove(packet, packet + start, packet_len - start);
            packet_len -= start;
        } else if (start == packet_len) {
            packet_len = 0;
        }
    }

    free(packet);
    syslog(LOG_USER | LOG_INFO, "Closed connection from %s", info->client_ip);
    close(client_fd);

    info->complete = 1;
    return NULL;
}

/* ========== main ========== */

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

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
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

#if !USE_AESD_CHAR_DEVICE
    // Make sure data file exists
    int df = open(DATAFILE, O_CREAT | O_APPEND, 0644);
    if (df != -1) close(df);
    /* Start timestamp thread */
    if (pthread_create(&timer_thread, NULL, timestamp_thread_func, NULL) != 0) {
        syslog(LOG_USER | LOG_ERR, "pthread_create for timer thread failed");
        close(server_fd);
        closelog();
        return -1;
    }
#endif
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

        struct client_thread *node = calloc(1, sizeof(*node));
        if (!node) {
            syslog(LOG_USER | LOG_ERR, "calloc failed for client_thread");
            close(client_fd);
            continue;
        }

        node->client_fd = client_fd;
        node->complete = 0;
        if (addrptr && inet_ntop(client_addr.ss_family, addrptr,
                                 node->client_ip, sizeof(node->client_ip)) == NULL) {
            strncpy(node->client_ip, "unknown", sizeof(node->client_ip));
            node->client_ip[sizeof(node->client_ip) - 1] = '\0';
        }

        if (pthread_create(&node->thread_id, NULL, client_thread_func, node) != 0) {
            syslog(LOG_USER | LOG_ERR, "pthread_create for client thread failed");
            close(client_fd);
            free(node);
            continue;
        }

        thread_list_add(node);

        /* Join and remove any threads that have completed */
        thread_list_cleanup_completed();
    }

    exit_requested = 1;

    if (server_fd != -1) {
        close(server_fd);
        server_fd = -1;
    }

#if !USE_AESD_CHAR_DEVICE
    /* Wait for timer thread to exit */
    pthread_join(timer_thread, NULL);
#endif
    /* Join any remaining client threads */
    thread_list_join_all();

    pthread_mutex_destroy(&data_mutex);
#if !USE_AESD_CHAR_DEVICE
    unlink(DATAFILE);
#endif
    closelog();

    return 0;
}
