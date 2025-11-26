/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
#include "aesd-circular-buffer.h"

int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Andrea Fuggetta"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    /**
     * TODO: handle open
     */
    filp->private_data = container_of(inode->i_cdev, struct aesd_dev, cdev);
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    filp->private_data = NULL;
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
    struct aesd_dev *dev;
    struct aesd_buffer_entry *entry = NULL;
    size_t entry_byte_off = 0;
    size_t bytes_avail_in_entry;
    size_t bytes_to_copy;
    ssize_t ret;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);

    /**
     * TODO: handle read
     */
   
   if (!filp || !buf || !f_pos) {
        PDEBUG("read: invalid args filp=%p buf=%p f_pos=%p", filp, buf, f_pos);
        return -EINVAL;
    }
    if (count == 0)
        return 0;

    dev = filp->private_data;


    if (mutex_lock_interruptible(&dev->lock)) {
        PDEBUG("read: mutex_lock_interruptible interrupted");
        return -ERESTARTSYS;
    }

    /* Map the linear file position */
    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->cmd_history, (size_t)*f_pos, &entry_byte_off);
    if (!entry) {
        mutex_unlock(&dev->lock);
        return 0; 
    }

    bytes_avail_in_entry = entry->size - entry_byte_off;
    bytes_to_copy = (bytes_avail_in_entry < count) ? bytes_avail_in_entry : count;

    if (copy_to_user(buf, (const char *)entry->buffptr + entry_byte_off, bytes_to_copy)) 
    {
        PDEBUG("read: copy_to_user failed (req=%zu)", bytes_to_copy);
        mutex_unlock(&dev->lock);
        return -EFAULT;
    }

    *f_pos += bytes_to_copy;
    ret = (ssize_t)bytes_to_copy;

    PDEBUG("read: copied=%zu new f_pos=%lld", bytes_to_copy, *f_pos);
    mutex_unlock(&dev->lock);
    return ret;
}

ssize_t aesd_write(struct file *filp, const char __user *ubuf, size_t count, loff_t *f_pos)
{
    struct aesd_dev *dev = filp->private_data;
    char *kbuf = NULL;
    ssize_t retval = count;
    void *newptr;
    size_t newsize;

    if (!filp || !ubuf || !f_pos) {
        PDEBUG("write: invalid args filp=%p buf=%p f_pos=%p", filp, ubuf, f_pos);
        return -EINVAL;
    }

    if (count == 0)
        return 0;

    dev = filp->private_data;
    if (!dev)
        return -EFAULT;

    kbuf = kmalloc(count, GFP_KERNEL);
    if (!kbuf) {
        PDEBUG("write: kmalloc failed for %zu bytes", count);
        return -ENOMEM;
    }

    if (copy_from_user(kbuf, ubuf, count)) {
        PDEBUG("write: copy_from_user failed");
        kfree(kbuf);
        return -EFAULT;
    }

    if (mutex_lock_interruptible(&dev->lock)) {
        PDEBUG("write: mutex_lock_interruptible interrupted");
        kfree(kbuf);
        return -ERESTARTSYS;
    }


    /* Append this user chunk to the accumulating buffer */
    newsize = dev->incomplete_cmd.size + count;
    newptr  = krealloc((void *)dev->incomplete_cmd.buffptr, newsize, GFP_KERNEL);
    if (!newptr) 
    {
      retval = -ENOMEM; 
      goto out_unlock_free; 
    }

    dev->incomplete_cmd.buffptr = (const char *)newptr;

    memcpy((char *)dev->incomplete_cmd.buffptr + dev->incomplete_cmd.size, kbuf, count);

    dev->incomplete_cmd.size = newsize;

    /*complete commands present in the accumulated buffer */
    for (;;) {
        char *base = (char *)dev->incomplete_cmd.buffptr;
        char *nl;

        if (!base || dev->incomplete_cmd.size == 0)
         break;
        nl = memchr(base, '\n', dev->incomplete_cmd.size);
        if (!nl)
         break; /* still incomplete */

        /* Length including newline */
        {
            size_t cmd_len = (size_t)(nl - base) + 1;
            const char *overwritten_ptr = NULL;

            if (dev->cmd_history.full) {
                uint8_t idx = dev->cmd_history.in_offs;
                overwritten_ptr = dev->cmd_history.entry[idx].buffptr;
            }

            /* Allocating buffer for this completed command */
            char *final_buf = kmalloc(cmd_len, GFP_KERNEL);
            if (!final_buf) 
            { 
             retval = -ENOMEM;
             goto out_unlock_free;
            }

            memcpy(final_buf, base, cmd_len);

            /* Pushing into teh circular buffer*/

            struct aesd_buffer_entry e = { .buffptr = (const char *)final_buf, .size = cmd_len };
            aesd_circular_buffer_add_entry(&dev->cmd_history, &e);

            /* Free the overwritten entry */
            if (overwritten_ptr)
              kfree((void *)overwritten_ptr);

            /* checking any tail after the newline as the new incomplete_cmd */
            {
                size_t tail_len = dev->incomplete_cmd.size - cmd_len;
                if (tail_len == 0) 
                {
                    kfree((void *)dev->incomplete_cmd.buffptr);
                    dev->incomplete_cmd.buffptr = NULL;
                    dev->incomplete_cmd.size = 0;
                } else {
                    char *tail = kmalloc(tail_len, GFP_KERNEL);
                    if (!tail) {
                     retval = -ENOMEM; 
                     goto out_unlock_free; 
                    }
                    memcpy(tail, base + cmd_len, tail_len);
                    kfree((void *)dev->incomplete_cmd.buffptr);
                    dev->incomplete_cmd.buffptr = (const char *)tail;
                    dev->incomplete_cmd.size = tail_len;
                }
            }
        }
        /* Loop in case multiple '\n' exist in the now-updated incomplete_cmd */
    }

  out_unlock_free:
    mutex_unlock(&dev->lock);
    kfree(kbuf);
    return retval;
}
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
    .llseek  = default_llseek,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */
 
    mutex_init(&aesd_device.lock);                 
    aesd_circular_buffer_init(&aesd_device.cmd_history); 
    aesd_device.incomplete_cmd.buffptr = NULL;
    aesd_device.incomplete_cmd.size = 0;

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
      struct aesd_buffer_entry *entry;
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */
 
    uint8_t idx;

    /* Free all command-history entries */
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.cmd_history, idx) {
    if (entry->buffptr) {
        kfree(entry->buffptr);
        entry->buffptr = NULL;
        entry->size = 0;
        }
    }

    /* Free any partially collected write-buffer */
    if (aesd_device.incomplete_cmd.buffptr) {
        kfree(aesd_device.incomplete_cmd.buffptr);
        aesd_device.incomplete_cmd.buffptr = NULL;
        aesd_device.incomplete_cmd.size = 0;
    }

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
