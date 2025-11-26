#include "aesdsocket_threading.h"
#include "freebsd_queue.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <syslog.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#define USE_AESD_CHAR_DEVICE 1

#define CONNECTION_PORT "9000"

#define LISTEN_QUEUE_SIZE 20

#define MAX_RECEIVED_LENGTH (20 * 1024)
#define MAX_FILE_LENGTH (128 * 1024)

#ifdef USE_AESD_CHAR_DEVICE
#define SERVER_FILE_NAME "/dev/aesdchar"
#else
#define SERVER_FILE_NAME "/var/tmp/aesdsocketdata"
#endif

bool bcaught_signal;
pthread_mutex_t mutex;

struct connection_thread_data *p_slist_params;

struct slist_thread_node {
			pthread_t slist_thread_id;
			struct connection_thread_data *slist_thread_data;
            SLIST_ENTRY(slist_thread_node) entries;
       };

SLIST_HEAD(slisthead, slist_thread_node) slist_thread_node_head;




// get sockaddr, IPv4 or IPv6:
void *get_client_IP_addr(struct sockaddr *client_addr)
{
	if (client_addr->sa_family == AF_INET) {
	return &(((struct sockaddr_in*)client_addr)->sin_addr);
	}

	return &(((struct sockaddr_in6*)client_addr)->sin6_addr);
}

static void sigaction_handler ( int signalnumber)
{
	if ( (signalnumber == SIGINT) || (signalnumber == SIGTERM) ) {
		bcaught_signal = true;
	}
}

void timestamp_alarm_handler (int signo)
{
	FILE *filetobewritten;
	char timestr[200];
	 time_t t;
	 struct tm *tmp;

	 t = time(NULL);
	 tmp = localtime(&t);

	 strftime(timestr, sizeof(timestr), "%a, %d %b %Y %T %z", tmp);

	/* Claim Mutex */
	pthread_mutex_lock(&mutex);
	/*printf ("Timestamping! : %s\n",timestr);*/

	filetobewritten = fopen(SERVER_FILE_NAME, "a");
	if (filetobewritten == NULL)
	{
		/*printf("Could not open the file\n");*/
		syslog(LOG_ERR,"Could not open the file");
		pthread_mutex_unlock(&mutex);
		return;
	}

	/* Append File with timestamp: */
	fputs("timestamp:", filetobewritten);
	fputs(timestr, filetobewritten);
	fputs("\n", filetobewritten);

	fclose(filetobewritten);

	/* Release Mutex */
	pthread_mutex_unlock(&mutex);
}

/* Thread function to manage each connection  */
void* connectionthreadfunc(void* thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    struct connection_thread_data* thread_func_args = (struct connection_thread_data *) thread_param;

    bool bEnd_of_line = 0;
    int max_received_length = MAX_RECEIVED_LENGTH;
	char received_buff[MAX_RECEIVED_LENGTH];
	char *send_buff = NULL;
	int received_length, send_length;
	FILE *filetobewritten;
	struct stat file_stat;

	size_t retsize = 0;

	thread_func_args->thread_complete_success = false;

    /* Claim Mutex */
    pthread_mutex_lock(thread_func_args->pmutex);

    filetobewritten = fopen(SERVER_FILE_NAME, "a");
	if (filetobewritten == NULL)
	{
	/*	printf("Could not open the file\n");*/
		syslog(LOG_ERR,"Could not open the file");
		pthread_mutex_unlock(thread_func_args->pmutex);
		return NULL;
	}


    while (bEnd_of_line == 0) {
		received_length = recv(thread_func_args->accept_socket_descriptor, &received_buff[0], max_received_length, 0);
		if ( received_length == -1) {
			syslog(LOG_ERR,"Error: could not receive\n");
		}

		/* Append the file */
		fputs(received_buff, filetobewritten);

	/*	printf("append the file with %d characters\n", received_length);*/

		/* Test if it was the end of the line*/
		if (received_buff[received_length-1] == '\n')
		{
			bEnd_of_line = 1;
			/*printf("end of the line\n");*/
		}
	}
	fclose(filetobewritten);
	/* send back the file */
	filetobewritten = fopen(SERVER_FILE_NAME, "r");
	stat(SERVER_FILE_NAME, &file_stat);
	send_length = MAX_FILE_LENGTH;
	send_buff = malloc(send_length);

	syslog(LOG_DEBUG,"File size is : %d\n", send_length);

	retsize = fread(send_buff, sizeof(char), send_length, filetobewritten);

	if ( retsize == -1 )
	{
		printf("Error retsize \n");
	}

	if (send(thread_func_args->accept_socket_descriptor, &send_buff[0], retsize, 0) == -1) {
		syslog(LOG_ERR,"Error: could not send\n");
	}

	close(thread_func_args->accept_socket_descriptor);
	if (filetobewritten != NULL) {
			fclose(filetobewritten);
		}
	if (send_buff != NULL){
		free(send_buff);
	}


    thread_func_args->thread_complete_success = true;

  /*  printf("end of the thread\n");*/

    /* Release Mutex */
    pthread_mutex_unlock(thread_func_args->pmutex);

    return thread_param;
}

/* Function to start a new connection thread */
bool start_connection_thread(pthread_t *thread, pthread_mutex_t *mutex,int accept_socket_descriptor, int numthread)
{
    int rc;

    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */

     /* Allocate Memory for thread_data */
     struct connection_thread_data *params = malloc(sizeof (struct connection_thread_data));

     p_slist_params = params;

     if (params == NULL)
     {
        /* No more memory to create threads */
        return false;
     }

     /* setup mutex and wait arguments */
     params->pmutex = mutex;
     params->thread_complete_success = false;
     params->accept_socket_descriptor = accept_socket_descriptor;

     /* Create thread */
     rc = pthread_create(thread, NULL, connectionthreadfunc, params);

     if ( rc != 0 ) {
   /*     printf("/n Failed to create the thread, error was %d",rc);*/
        return false;
    }


    return true;
}



int main(int argc, char *argv[])
{

    int return_status;
    int socket_descriptor;
	int accept_socket_descriptor;
    struct addrinfo socket_requirements;
    struct addrinfo *server_info;
    struct addrinfo *socket_test;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_size;
    char client_ip_addr[INET6_ADDRSTRLEN];

    int bDaemonmode = 0;
    int sock_option=1;
    struct sigaction signal_management;
    
    pthread_t thread_ID;

    struct slist_thread_node *pnew_slist_thread_node;
    struct slist_thread_node *thread_node_temp;
    struct slisthead slist_thread_head;


    SLIST_INIT(&slist_thread_head);

    int numthread = 0;

    int num_slist_thread = 0;

    FILE *filetobecreated;
#ifndef USE_AESD_CHAR_DEVICE
    struct itimerval delay;
    int ret;
    
    signal (SIGALRM, timestamp_alarm_handler);

    delay.it_value.tv_sec = 1;
    delay.it_value.tv_usec = 0;
    delay.it_interval.tv_sec = 10;
    delay.it_interval.tv_usec = 0;
#endif
    int retvalue = 0;

    /* install netcat */
#ifdef INSTALL_NETCAT
    retvalue = system("./install_nc.sh");
#endif

    bcaught_signal = false;

    memset(&signal_management, 0, sizeof(struct sigaction));

    signal_management.sa_handler = sigaction_handler;

    pthread_mutex_init(&mutex, NULL);


	/* Activate syslog */
	openlog(NULL,0,LOG_USER);
	
	if (argc > 2)
	{
	/*	printf("Error, too many arguments");*/
		syslog(LOG_ERR,"Invalid Number of arguments: %d , it should be 1 or 2", (argc - 1));
		return -1;
	}
	syslog(LOG_DEBUG,"Good Number of parameters");
	
	if (argc == 2) {
		if ( strcmp(argv[1],"-d") != 0 ) {
			syslog(LOG_ERR,"Invalid Argument: only -d is accepted");
			return -1;
		} else {
			bDaemonmode = 1;
		}
	} else {
		bDaemonmode = 0;
	}

	if (bDaemonmode == 1) {
		syslog(LOG_DEBUG,"Daemon mode started");
		retvalue = daemon(0,0);
	}

	/* Call to the getaddrinfo function */
	memset(&socket_requirements, 0, sizeof socket_requirements);
	
	socket_requirements.ai_family = AF_INET;
	socket_requirements.ai_socktype = SOCK_STREAM;
	socket_requirements.ai_flags = AI_PASSIVE;
	
	if ( ( return_status = getaddrinfo(NULL, CONNECTION_PORT, &socket_requirements, &server_info) ) != 0) {
	    printf("Error during getaddrinfo : %s\n", gai_strerror(return_status) );
		syslog(LOG_ERR,"Error during getaddrinfo : %s\n", gai_strerror(return_status));
		return -1;
	}
	
	
	/* Find a good socket */
	for ( socket_test = server_info; socket_test != NULL; socket_test = socket_test->ai_next) {
	    /* test socket */
	    socket_descriptor = socket(socket_test->ai_family, socket_test->ai_socktype, socket_test->ai_protocol);
	    
	    if ( socket_descriptor == -1) {
	        /* this is not a valid one */
	        continue;
	    } else {

	    	if (setsockopt(socket_descriptor, SOL_SOCKET, SO_REUSEADDR, &sock_option,sizeof(int)) == -1) {
	    		printf("Unable to setsockopt\n");
	    		syslog(LOG_ERR,"Unable to setsockopt\n");
	    		exit(1);
	    	}
	    	/* test bind */
	        if ( bind(socket_descriptor, socket_test->ai_addr, socket_test->ai_addrlen) == -1) {
	            /* this is not a valid one */
	            close(socket_descriptor);
	            continue;
	        } else {
	            /* we found a good one */
	            break;
	          }
	    }
    }
	
	/* we can free the structure */
	freeaddrinfo(server_info);
	
	/* Test if we found a good one */
	if (socket_test == NULL) {
	    printf("Unable to find a good socket and bind\n");
		syslog(LOG_ERR,"Unable to find a good socket and bind\n");
		return -1;
	}
	
	sigaction(SIGTERM, &signal_management, NULL);
	sigaction(SIGINT, &signal_management, NULL);

	/* listening */
	if ( listen(socket_descriptor, LISTEN_QUEUE_SIZE) == -1) {
	    printf("Error: could not listen\n");
		syslog(LOG_ERR,"Error: could not listen\n");
		return -1;
	}

	filetobecreated = fopen(SERVER_FILE_NAME, "wa");
	if (filetobecreated == NULL)
	{
		printf("Could not create the file\n");
		syslog(LOG_ERR,"Could not create the file");
		return -1;
	}

	if (filetobecreated != NULL) {
		fclose(filetobecreated);
	}

	/* Launch timestamping */
	#ifndef USE_AESD_CHAR_DEVICE
	ret = setitimer (ITIMER_REAL, &delay, NULL);
	if (ret) {
		printf("Error, can not set timestamping");
		syslog(LOG_ERR,"Error, can not set timestamping");
		return -1;
	}
	#endif

	while(1) {

		client_addr_size = sizeof client_addr;
		accept_socket_descriptor = accept(socket_descriptor, (struct sockaddr *)&client_addr, &client_addr_size);

		if ( (bcaught_signal == true) || (accept_socket_descriptor == -1) ) {

			/* Delete All sling list elements */
			while (!SLIST_EMPTY(&slist_thread_head)) {           /* List deletion */
				pnew_slist_thread_node = SLIST_FIRST(&slist_thread_head);
			   SLIST_REMOVE_HEAD(&slist_thread_head, entries);
			   p_slist_params = pnew_slist_thread_node->slist_thread_data;

			   pthread_join(pnew_slist_thread_node->slist_thread_id, NULL);
			   if (p_slist_params != NULL)
			   {
				   free(p_slist_params);
			   }

			   free(pnew_slist_thread_node);
		   }

			if (accept_socket_descriptor == -1) {
				printf("Exit from accept\n");
				syslog(LOG_DEBUG,"Exit from accept\n");
				return 0;
			}

		/*	printf("Caught signal, exiting\n");*/
			syslog(LOG_DEBUG,"Caught signal, exiting");
			#ifndef USE_AESD_CHAR_DEVICE
			remove(SERVER_FILE_NAME);
			#endif
			return 0;
		}



		inet_ntop(client_addr.ss_family,get_client_IP_addr((struct sockaddr *)&client_addr),client_ip_addr, sizeof client_ip_addr);
	/*	printf("server: got connection from %s\n", client_ip_addr);*/
		syslog(LOG_DEBUG,"Accepted connection from %s\n", client_ip_addr);

		/* We can start a thread to manage this connection */
		start_connection_thread(&thread_ID, &mutex, accept_socket_descriptor, numthread);


		/* We put the thread in the singly list */

		pnew_slist_thread_node = malloc(sizeof(struct slist_thread_node));      /* Insert at the head */
		pnew_slist_thread_node->slist_thread_id = thread_ID;
		pnew_slist_thread_node->slist_thread_data = p_slist_params;
		SLIST_INSERT_HEAD(&slist_thread_head, pnew_slist_thread_node, entries);

		numthread++;

		num_slist_thread = 0;
		/* We check if some threads are completed */
		SLIST_FOREACH_SAFE(pnew_slist_thread_node, &slist_thread_head, entries, thread_node_temp) {
			/* Test if thread is completed */
	/*		printf("Test Thread number : %d\n",num_slist_thread);*/
			num_slist_thread++;
			if (pnew_slist_thread_node->slist_thread_data->thread_complete_success == true)
			{
		/*		printf("Thread Complete\n");*/
				/* we delete the thread */
				p_slist_params = pnew_slist_thread_node->slist_thread_data;

			   pthread_join(pnew_slist_thread_node->slist_thread_id, NULL);
			   if (p_slist_params != NULL)
			   {
				   free(p_slist_params);
			   }

				SLIST_REMOVE(&slist_thread_head, pnew_slist_thread_node, slist_thread_node, entries);
				free(pnew_slist_thread_node);
			}
/*			else
			{
				printf("Thread Not Complete !!\n");
			}
*/
		}

		if ( retvalue == -1)
		{
			printf("Error in retvalue !!\n");
		}

	}
	return 0;
}