#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    //struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    struct thread_data* thread_func_args = (struct thread_data *) thread_param;

    // sleeps @param wait_to_obtain_ms number of milliseconds
    usleep(thread_func_args->wait_to_obtain_ms * 1000);
    // obtains the mutex in @param mutex
    if(pthread_mutex_lock(thread_func_args->mutex) != 0)
    {
        ERROR_LOG("Couldn't lock the mutex");
        thread_func_args->thread_complete_success = false;
        return thread_func_args;
    }
    // then holds for @param wait_to_release_ms milliseconds, then releases
    usleep(thread_func_args->wait_to_release_ms * 1000);
    if(pthread_mutex_unlock(thread_func_args->mutex) != 0)
    {
        ERROR_LOG("Couldn't unlock the mutex");
        thread_func_args->thread_complete_success = false;
        return thread_func_args;
    }

    // setting success flag
    thread_func_args->thread_complete_success = true;
    return thread_func_args;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */
    
    // ALlocate memory for thread_data
    struct thread_data * thread_param = malloc(sizeof(struct thread_data));
    if (!thread_param) {
        ERROR_LOG("Error getting thread parameters");
        return false;
    }
    
    // setup mutex and wait arguments
    thread_param->mutex = mutex;
    thread_param->wait_to_obtain_ms = wait_to_obtain_ms;
    thread_param->wait_to_release_ms = wait_to_release_ms;

    // pass thread_data to created thread using threadfunc() as entry point
    int ret;
    ret = pthread_create(thread, NULL, threadfunc, thread_param);
    if (ret != 0)
    {
        ERROR_LOG("pthread_create error");
        free(thread_param);
        return false;
    }

    return true;
}

