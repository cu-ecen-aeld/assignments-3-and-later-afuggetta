#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>  
#include <syslog.h>

int main(int argc, char* argv[])
{
    // Set logger up
    openlog("finder-app", LOG_PID | LOG_CONS, LOG_USER);

    if (argc < 3)
    {
        syslog(LOG_ERR, "Error: missing parameter(s). You need to provide two arguments");
        closelog();
        return 1;
    }

    // Store arguments into variables
    char *file_path = malloc(strlen(argv[1]) + 1);
    strcpy(file_path, argv[1]);

    char *string_to_write = malloc(strlen(argv[2]) + 1);
    strcpy(string_to_write, argv[2]);

    syslog(LOG_DEBUG, "Writing <%s> to <%s>", string_to_write, file_path);

    int fd;
    fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

    if (fd == -1)
    {
        syslog(LOG_ERR, "Error: Failed to create file!");
        closelog();
        return 1;
    }
    // write to the file
    ssize_t nf;
    nf = write(fd, string_to_write, strlen(string_to_write));
    if (nf == -1)
    {
        syslog(LOG_ERR, "Error: Failed to write to file!");
        close(fd);
        closelog();
        return 1;
    }
    close(fd);
    closelog();
    return 0;
}