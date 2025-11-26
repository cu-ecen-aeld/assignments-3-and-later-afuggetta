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
#endif
#include "aesd-circular-buffer.h"

struct aesd_dev
{
    struct cdev cdev;                     /* Char device structure      */
    struct aesd_circular_buffer buffer;   /* Our circular buffer        */
    struct mutex lock;                    /* Mutex for read/write       */
    char   *partial_buf;                  /* Accumulated partial command*/
    size_t  partial_size;                 /* Size of partial_buf        */
};

int aesd_open(struct inode *inode, struct file *filp);
int aesd_release(struct inode *inode, struct file *filp);
ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,loff_t *f_pos);
ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,loff_t *f_pos);
int aesd_init_module(void);
void aesd_cleanup_module(void);

#endif /* AESD_CHAR_DRIVER_AESDCHAR_H_ */