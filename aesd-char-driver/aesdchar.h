/*
 * aesdchar.h
 *
 *  Created on: Oct 23, 2019
 *      Author: Dan Walkes
 */

#ifndef AESD_CHAR_DRIVER_AESDCHAR_H_
#define AESD_CHAR_DRIVER_AESDCHAR_H_

#define AESD_DEBUG 1  //Remove comment on this line to enable debug

#undef PDEBUG             /* undef it, just in case */
#ifdef AESD_DEBUG
#  ifdef __KERNEL__
     /* This one if debugging is on, and kernel space */
#    define PDEBUG(fmt, args...) printk( KERN_DEBUG "aesdchar: " fmt, ## args)
#  else
     /* This one for user space */
#    define PDEBUG(fmt, args...) fprintf(stderr, fmt, ## args)
#  endif
#else
#  define PDEBUG(fmt, args...) /* not debugging: nothing */
#endif

#ifdef __KERNEL__
#include <linux/cdev.h>
#include <linux/mutex.h>
#include "aesd-circular-buffer.h"
#endif

struct aesd_dev
{
    /**
     * TODO: Add structure(s) and locks needed to complete assignment requirements
     */
    struct mutex lock;                       // Protects concurrent access
    struct aesd_circular_buffer cmd_history; // Holds 10 most recent completed commands
    struct aesd_buffer_entry incomplete_cmd; // Data from write() before newline is received
    struct cdev cdev;                        // Char device structure
};


#endif /* AESD_CHAR_DRIVER_AESDCHAR_H_ */
