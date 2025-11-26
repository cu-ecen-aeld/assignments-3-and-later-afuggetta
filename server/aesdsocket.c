#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>

#include <pthread.h>
#include <sys/queue.h>
#include <time.h>

/* ========================== Config ========================== */
#define SERVICE_PORT "9000" 

#ifndef USE_AESD_CHAR_DEVICE
#define USE_AESD_CHAR_DEVICE 1  // default ON
#endif

#if USE_AESD_CHAR_DEVICE
#define DATA_FILE "/dev/aesdchar"
#else
#define DATA_FILE "/var/tmp/aesdsocketdata"
#endif

/* ========================== Global state ========================== */
static volatile sig_atomic_t g_shutdown_requested = 0; //flag set when signals are called
static volatile sig_atomic_t g_last_signal = 0;   //flag to identify which signal

static pthread_mutex_t g_file_mutex = PTHREAD_MUTEX_INITIALIZER;

/*client info struct */
struct client_ctx {
    int  client_fd; 
    char client_ip[INET6_ADDRSTRLEN]; //readable address
};

//complete one client node thread struct
struct thread_node {
    pthread_t tid;
    _Atomic bool done;  //the flag to check if the threads are completed before to join them and making this atomic
    struct client_ctx ctx;
    SLIST_ENTRY(thread_node) entries;
};

SLIST_HEAD(thread_list_head, thread_node);
static struct thread_list_head g_threads = SLIST_HEAD_INITIALIZER(g_threads);

/* ========================== Logging helpers ========================== */
#define LOGI(fmt, ...)  syslog(LOG_INFO, "[OK]  " fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...)  syslog(LOG_ERR,  "[ERR] " fmt, ##__VA_ARGS__)

/* ========================== Signal handling ========================== */
static void termination_signal_handler(int signo)
{
    g_last_signal = signo;
    g_shutdown_requested = 1;

    if (signo == SIGINT) {
        syslog(LOG_WARNING, "Caught SIGINT (Ctrl+C) — shutting down");
    } else if (signo == SIGTERM) {
        syslog(LOG_WARNING, "Caught SIGTERM — shutting down");
    } else {
        syslog(LOG_WARNING, "Caught signal %d — shutting down", signo);
    }
}

static ssize_t write_all(int fd, const void *buf, size_t count)
{
    const uint8_t *p = (const uint8_t *)buf; 
    size_t remaining = count;

    while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);
        if (n < 0) {
            if (errno == EINTR) 
              continue; 
            return -1;
        }
        p += (size_t)n;
        remaining -= (size_t)n;
    }
    return (ssize_t)count;
}

/* ========================== Daemonize ========================== */
static int daemonize_self(void)
{
    pid_t pid;
    pid = fork();
    if (pid < 0)
    {
        LOGI("Fork failed");
        return -1;
    }

    if (pid > 0)
    {
        exit(EXIT_SUCCESS); //exit from the parent process
    }

    if (setsid() < 0)
    {
        LOGI("Creating the new session failed");
        return -1;
    }
    if (chdir("/") == -1)
    {
       LOGI("Changing working directory to the root failed");
        return -1;
    }

    /* Close std fds and redirect to /dev/null */
    close(STDIN_FILENO); 
    close(STDOUT_FILENO); 
    close(STDERR_FILENO);
    
    int devnull = open("/dev/null", O_RDWR);
    
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        
        if (devnull > 2) 
         close(devnull);
    }
    LOGI("Daemonized successfully");
    return 0;
}

/* ================= Timestamp thread: appends every 10 seconds ================= */
#if !USE_AESD_CHAR_DEVICE
static void *timestamp_worker(void *arg)
{
    (void)arg;
    while (!g_shutdown_requested) {

        /* Sleep in 1s slices just to react quickly to shutdown */
        for (int i = 0; i < 10 && !g_shutdown_requested; ++i) 
           sleep(1);
        if (g_shutdown_requested) 
            break;
            
            
       time_t now = time(NULL);
       struct tm tm_local;
       if (localtime_r(&now, &tm_local) == NULL)
          continue;

       char tbuf[128];
       size_t n = strftime(tbuf, sizeof tbuf, "%a, %d %b %Y %T %z", &tm_local);
       if (n == 0)
         continue;

       pthread_mutex_lock(&g_file_mutex);

       int fd = open(DATA_FILE, O_CREAT | O_WRONLY, 0644);
       if (fd == -1) {
         LOGI("failed to open the file");
         pthread_mutex_unlock(&g_file_mutex);
         return NULL;
        }
        
        
       /* SEnding the complete line */
       char line[192];
       int len = snprintf(line, sizeof line, "timestamp: %s\n", tbuf);
       if (len > 0 && lseek(fd, 0, SEEK_END) != -1) {
           write_all(fd, line, (size_t)len);
           fsync(fd);
        }

     close(fd);
     pthread_mutex_unlock(&g_file_mutex);

    }
    return NULL;
}
#endif

static void *client_worker(void *arg)
{
    struct thread_node *node = (struct thread_node *)arg;
    int client_fd = node->ctx.client_fd;
    const char *client_ip = node->ctx.client_ip;

    LOGI("Handling connection from %s", client_ip ? client_ip : "unknown");

    int data_append_fd = open(DATA_FILE, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (data_append_fd < 0) {
        LOGE("open(%s for append) failed: %s", DATA_FILE, strerror(errno));
        goto out;
    }
    LOGI("Opened %s for append", DATA_FILE);

    char *pending = NULL;
    size_t pending_cap = 0;
    size_t pending_len = 0;

    while (!g_shutdown_requested) {
        char recv_buf[1024];
        ssize_t rcvd = recv(client_fd, recv_buf, sizeof(recv_buf), 0);
        if (rcvd == 0) {
            LOGI("Client %s closed connection", client_ip ? client_ip : "unknown");
            break;
        }
        if (rcvd < 0) {
            if (errno == EINTR) 
              continue;
            LOGE("recv failed: %s", strerror(errno));
            break;
        }
        LOGI("Received %zd bytes from %s", rcvd, client_ip ? client_ip : "unknown");

        /* To Grow pending buffer */

        if (pending_len + (size_t)rcvd > pending_cap) {
            size_t new_cap = pending_cap ? pending_cap : 2048;
            while (pending_len + (size_t)rcvd > new_cap) new_cap *= 2;
            char *new_buf = realloc(pending, new_cap);
            
            if (!new_buf) {
             LOGE("realloc failed"); 
             break; 
            }
            
            pending = new_buf; pending_cap = new_cap;
        }
        
        memcpy(pending + pending_len, recv_buf, (size_t)rcvd);
        pending_len += (size_t)rcvd;

        /* Processing complete packets ending with '\n' */
        size_t scan_start = 0;
        for (;;) {
            if (scan_start >= pending_len) 
               break;
            char *nl = memchr(pending + scan_start, '\n', pending_len - scan_start);
            if (!nl) 
               break;

            size_t pkt_end = (size_t)(nl - pending) + 1;
            size_t pkt_len = pkt_end - scan_start;

            pthread_mutex_lock(&g_file_mutex);

            if (write_all(data_append_fd, pending + scan_start, pkt_len) < 0) {
                pthread_mutex_unlock(&g_file_mutex);
                LOGE("write(%s) failed: %s", DATA_FILE, strerror(errno));
                goto out;
            }
           
            LOGI("Appended %zu bytes to %s", pkt_len, DATA_FILE);

            /* Send the entire file back */
            int data_read_fd = open(DATA_FILE, O_RDONLY);
            if (data_read_fd < 0) {
                pthread_mutex_unlock(&g_file_mutex);
                LOGE("open(%s for read) failed: %s", DATA_FILE, strerror(errno));
                goto out;
            }

            ssize_t total_sent = 0;
            for (;;) {
                char outbuf[1024];
                ssize_t rn = read(data_read_fd, outbuf, sizeof(outbuf));
                if (rn < 0) {
                    if (errno == EINTR) 
                       continue;
                    LOGE("read(%s) failed: %s", DATA_FILE, strerror(errno));
                    close(data_read_fd);
                    pthread_mutex_unlock(&g_file_mutex);
                    goto out;
                }
                if (rn == 0) 
                   break;

                if (write_all(client_fd, outbuf, (size_t)rn) < 0) {
                    LOGE("send to client failed: %s", strerror(errno));
                    close(data_read_fd);
                    pthread_mutex_unlock(&g_file_mutex);
                    goto out;
                }
                
                
                total_sent += rn;
            }
            
            
            close(data_read_fd);
            
            pthread_mutex_unlock(&g_file_mutex);
            
            LOGI("Sent %zd bytes of %s to client %s", total_sent, DATA_FILE, client_ip ? client_ip : "unknown");

            scan_start = pkt_end;
        }

        /* Compact any partial line left over */
        if (scan_start > 0) {
            size_t remain = pending_len - scan_start;
            memmove(pending, pending + scan_start, remain);
            pending_len = remain;
        }
    }

out:
    if (data_append_fd >= 0) 
      close(data_append_fd);
    free(pending);
    LOGI("Finished connection with %s", client_ip ? client_ip : "unknown");
    
    node->done = true;   /* mark for main thread to join & clean */
    return NULL;
}



/* ========================== Main ========================== */
int main(int argc, char *argv[])
{
    bool run_as_daemon = false;
    if (argc == 2 && strcmp(argv[1], "-d") == 0)
        run_as_daemon = true;

    openlog("aesdsocket", LOG_PID, LOG_USER);
    LOGI("Program start");
   #if USE_AESD_CHAR_DEVICE
      LOGI("MODE: char device, endpoint");
   #else
      LOGI("MODE: file-backed, path");
   #endif

    /* Install signal handlers */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = termination_signal_handler;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) != 0) {
        LOGE("sigaction(SIGINT) failed: %s", strerror(errno));
        closelog();
        return EXIT_FAILURE;
    }
    LOGI("Installed SIGINT handler");

    if (sigaction(SIGTERM, &sa, NULL) != 0) {
        LOGE("sigaction(SIGTERM) failed: %s", strerror(errno));
        closelog();
        return EXIT_FAILURE;
    }
    LOGI("Installed SIGTERM handler");
#if !USE_AESD_CHAR_DEVICE
    /* Just to ensure the data file exists */
    int touch_fd = open(DATA_FILE, O_CREAT | O_WRONLY, 0644);
    
    if (touch_fd < 0) {
    
        LOGE("open(%s) failed: %s", DATA_FILE, strerror(errno));
        closelog();
        return EXIT_FAILURE;
    }
    
    close(touch_fd);
    
    LOGI("Ensured %s exists (or created)", DATA_FILE);
#endif
    /* Resolve addresses to bind on port 9000 */
    struct addrinfo hints, *results = NULL, *ai = NULL;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;   /* IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;

    int gai = getaddrinfo(NULL, SERVICE_PORT, &hints, &results); //get all the addr in this local system
    if (gai != 0) {
        LOGE("getaddrinfo(%s) failed: %s", SERVICE_PORT, gai_strerror(gai));
        closelog();
        return EXIT_FAILURE;
    }
    
    LOGI("getaddrinfo success for port %s", SERVICE_PORT);

    /* Create and bind the listening socket */
    
    int listen_fd = -1;
    
    for (ai = results; ai != NULL; ai = ai->ai_next) {
    
        listen_fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol); //create the communication end point
        
        if (listen_fd < 0) {
            LOGE("socket() failed on candidate: %s", strerror(errno));
            continue;
        }

        int reuse = 1;
        
        if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0) {
            LOGE("setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));
            close(listen_fd); listen_fd = -1; continue;
        }

        
        if (bind(listen_fd, ai->ai_addr, ai->ai_addrlen) == 0) { 
            LOGI("bind success on port %s", SERVICE_PORT);
            break;
        } else {
            LOGE("bind failed: %s", strerror(errno));
            close(listen_fd); listen_fd = -1; continue;
        }
    }
    freeaddrinfo(results);

    if (listen_fd < 0) {
        LOGE("Could not bind to any address on port %s", SERVICE_PORT);
        closelog(); return EXIT_FAILURE;
    }

    /* Daemonize after successful bind, before listen/accept */
    if (run_as_daemon) {
        if (daemonize_self() != 0) {
            LOGE("daemonize failed");
            close(listen_fd);
             closelog(); 
             return EXIT_FAILURE;
        }
    }
 // make the listen as passive to the server
    if (listen(listen_fd, SOMAXCONN) != 0) {
        LOGE("listen failed: %s", strerror(errno));
        close(listen_fd); 
        closelog(); 
        return EXIT_FAILURE;
    }
    LOGI("Listening on TCP port %s", SERVICE_PORT);
#if !USE_AESD_CHAR_DEVICE

    /* timestamp thread  */
    
    pthread_t ts_tid;
    
    int ts_rc = pthread_create(&ts_tid, NULL, timestamp_worker, NULL);
    
    if (ts_rc != 0) {
    
        LOGE("timestamp pthread_create failed: %s", strerror(ts_rc));
    }
#endif

    /* ========================== Accept loop (multi-client) ========================== */
    while (!g_shutdown_requested) {

        struct sockaddr_storage client_addr;
        
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
        
        if (client_fd < 0) {
        
            if (errno == EINTR && g_shutdown_requested)
              break;
              
            else 
              LOGE("accept failed: %s", strerror(errno));
        } else {
            //convert the binary addr to the human readable format
            char client_ip[INET6_ADDRSTRLEN] = {0};
            void *addr_ptr = NULL;

            if (client_addr.ss_family == AF_INET) {
                addr_ptr = &((struct sockaddr_in *)&client_addr)->sin_addr;
            } else if (client_addr.ss_family == AF_INET6) {
                addr_ptr = &((struct sockaddr_in6 *)&client_addr)->sin6_addr;
            }

            if (addr_ptr) inet_ntop(client_addr.ss_family, addr_ptr, client_ip, sizeof(client_ip));
            
            LOGI("Accepted connection from %s", client_ip[0] ? client_ip : "unknown");

            //allocate the zero initialized memory for the node
            struct thread_node *node = calloc(1, sizeof(*node));
            
            if (!node) {
            
                LOGE("calloc thread_node failed");
                close(client_fd);
                
            } else {
            
                node->ctx.client_fd = client_fd;
                node->done = false;
                

                  //creating thread for each client connection

                int rc = pthread_create(&node->tid, NULL, client_worker, node);
                
                if (rc != 0) {
                
                    LOGE("pthread_create failed: %s", strerror(rc));
                    
                    close(client_fd);
                    
                    free(node);
                    
                } else {
                
                    SLIST_INSERT_HEAD(&g_threads, node, entries);//adding that thread to the list
                }
            }
        }

        /*just removing the threads that has finished */
        
        struct thread_node *cur = SLIST_FIRST(&g_threads);
        
        while (cur) {
            struct thread_node *next = SLIST_NEXT(cur, entries);
            
            if (cur->done) {
            
                pthread_join(cur->tid, NULL);
                
                SLIST_REMOVE(&g_threads, cur, thread_node, entries);
                
                if (cur->ctx.client_fd >= 0) 
                  close(cur->ctx.client_fd);
                
                free(cur);
            }
            cur = next;
        }
    }

    /* Stop new connections */
    
    if (close(listen_fd) != 0) 
      LOGE("close(listen_fd) failed: %s", strerror(errno));
    else                       
      LOGI("Closed listening socket");

    /* Final join for any remaining client threads after closing the listening socket */
    // safer case to join 
    
    struct thread_node *cur = SLIST_FIRST(&g_threads);
    
    while (cur) {
        struct thread_node *next = SLIST_NEXT(cur, entries);
        pthread_join(cur->tid, NULL);
        if (cur->ctx.client_fd >= 0) 
          close(cur->ctx.client_fd);
        free(cur);
        cur = next;
    }
    SLIST_INIT(&g_threads);
#if !USE_AESD_CHAR_DEVICE
    /* Join the timestamp thread last */
    if (ts_rc == 0) 
      pthread_join(ts_tid, NULL);

    /* Remove the data file  */
    if (unlink(DATA_FILE) != 0) {
        if (errno == ENOENT) 
           LOGI("%s already removed", DATA_FILE);
        else                 
           LOGE("unlink(%s) failed: %s", DATA_FILE, strerror(errno));
    } else {
        LOGI("Removed %s", DATA_FILE);
    }
#endif
    /* Final exit reason to know if any signal occured */

    if (g_last_signal == SIGINT)  
       LOGI("Exiting after SIGINT");
    else if (g_last_signal == SIGTERM) 
       LOGI("Exiting after SIGTERM");
    else                               
       LOGI("Exiting normally");

    closelog();
    return EXIT_SUCCESS;
}