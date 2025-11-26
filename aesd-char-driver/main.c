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
#include <linux/mutex.h>
#include "aesdchar.h"
#include "aesd-circular-buffer.h"
#include "aesd_ioctl.h"

#define AESD_DEBUG 1
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Andrea Fuggetta"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

static int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *dev;

    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;
    return 0;
}

static int aesd_release(struct inode *inode, struct file *filp)
{
    return 0;
}

static ssize_t aesd_read(struct file *filp, char __user *buf,
                         size_t count, loff_t *f_pos)
{
    struct aesd_dev *dev = filp->private_data;
    ssize_t total_read = 0;
    size_t offset;
    struct aesd_buffer_entry *entry;
    size_t entry_off;
    size_t to_copy;

    if (!dev)
        return -EFAULT;

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    offset = *f_pos;

    while (count > 0) {
        entry = aesd_circular_buffer_find_entry_offset_for_fpos(
                    &dev->buffer, offset, &entry_off);
        if (!entry || entry->size == 0) {
            /* No more data available */
            break;
        }

        to_copy = entry->size - entry_off;
        if (to_copy > count)
            to_copy = count;

        if (copy_to_user(buf + total_read,
                         entry->buffptr + entry_off,
                         to_copy)) {
            if (total_read == 0)
                total_read = -EFAULT;
            goto out_unlock;
        }

        total_read += to_copy;
        offset     += to_copy;
        count      -= to_copy;
    }

    *f_pos = offset;

out_unlock:
    mutex_unlock(&dev->lock);
    return total_read;
}

static ssize_t aesd_write(struct file *filp, const char __user *buf,
                          size_t count, loff_t *f_pos)
{
    struct aesd_dev *dev = filp->private_data;
    ssize_t retval = count;
    char *user_buf = NULL;
    char *combined = NULL;
    size_t needed;
    size_t pos = 0;
    size_t i;

    (void)f_pos; /* Ignored for this assignment */

    if (!dev)
        return -EFAULT;

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    /* Copy user data */
    user_buf = kmalloc(count, GFP_KERNEL);
    if (!user_buf) {
        retval = -ENOMEM;
        goto out_unlock;
    }

    if (copy_from_user(user_buf, buf, count)) {
        retval = -EFAULT;
        goto out_unlock;
    }

    /* Build combined = partial_buf + user_buf */
    needed = dev->partial_size + count;
    combined = kmalloc(needed, GFP_KERNEL);
    if (!combined) {
        retval = -ENOMEM;
        goto out_unlock;
    }

    if (dev->partial_buf && dev->partial_size > 0)
        memcpy(combined, dev->partial_buf, dev->partial_size);

    memcpy(combined + dev->partial_size, user_buf, count);

    /* We no longer need old partial */
    kfree(dev->partial_buf);
    dev->partial_buf  = NULL;
    dev->partial_size = 0;

    /* Parse combined for complete lines ending in '\n' */
    pos = 0;
    for (i = 0; i < needed; i++) {
        if (combined[i] == '\n') {
            size_t line_len = i - pos + 1; /* include '\n' */
            struct aesd_buffer_entry new_entry;
            struct aesd_buffer_entry *old_entry;

            new_entry.buffptr = kmalloc(line_len, GFP_KERNEL);
            if (!new_entry.buffptr) {
                retval = -ENOMEM;
                goto out_unlock;
            }
            new_entry.size = line_len;
            memcpy((char *)new_entry.buffptr, combined + pos, line_len);

            /*
             * If buffer is full, next add will overwrite entry at in_offs.
             * Free that entry first.
             */
            if (dev->buffer.full) {
                old_entry = &dev->buffer.entry[dev->buffer.in_offs];
                if (old_entry->buffptr) {
                    kfree(old_entry->buffptr);
                    old_entry->buffptr = NULL;
                    old_entry->size = 0;
                }
            }

            aesd_circular_buffer_add_entry(&dev->buffer, &new_entry);

            pos = i + 1; /* start of next potential line */
        }
    }

    /* Remaining bytes after last '\n' become new partial */
    if (pos < needed) {
        dev->partial_size = needed - pos;
        dev->partial_buf  = kmalloc(dev->partial_size, GFP_KERNEL);
        if (!dev->partial_buf) {
            retval = -ENOMEM;
            goto out_unlock;
        }
        memcpy(dev->partial_buf, combined + pos, dev->partial_size);
    } else {
        dev->partial_buf  = NULL;
        dev->partial_size = 0;
    }

out_unlock:
    if (combined)
        kfree(combined);
    if (user_buf)
        kfree(user_buf);
    mutex_unlock(&dev->lock);
    return retval;
}

static size_t aesd_get_buffer_size(struct aesd_circular_buffer *buffer)
{
    size_t total = 0;
    uint8_t idx;
    struct aesd_buffer_entry *entry;

    AESD_CIRCULAR_BUFFER_FOREACH(entry, buffer, idx) {
        if (entry->buffptr && entry->size > 0) {
            total += entry->size;
        }
    }
    return total;
}

static loff_t aesd_llseek(struct file *filp, loff_t offset, int whence)
{
    struct aesd_dev *dev = filp->private_data;
    loff_t new_pos;
    loff_t filesize;

    if (!dev)
        return -EINVAL;

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    /* Total size of data currently stored in the circular buffer */
    filesize = (loff_t)aesd_get_buffer_size(&dev->buffer);

    switch (whence) {
    case SEEK_SET:
        new_pos = offset;
        break;

    case SEEK_CUR:
        new_pos = filp->f_pos + offset;
        break;

    case SEEK_END:
        new_pos = filesize + offset;
        break;

    default:
        mutex_unlock(&dev->lock);
        return -EINVAL;
    }

    /* Enforce bounds: only allow [0, filesize] */
    if (new_pos < 0 || new_pos > filesize) {
        mutex_unlock(&dev->lock);
        return -EINVAL;
    }

    filp->f_pos = new_pos;
    mutex_unlock(&dev->lock);
    return new_pos;
}

static long aesd_unlocked_ioctl(struct file *filp,
                                unsigned int cmd,
                                unsigned long arg)
{
    struct aesd_dev *dev = filp->private_data;
    struct aesd_seekto seekto;
    uint8_t entries;
    uint8_t i;
    size_t cumulative = 0;
    struct aesd_buffer_entry *entry;
    loff_t new_pos;
    uint32_t write_cmd;
    uint32_t write_cmd_offset;

    if (!dev)
        return -EINVAL;

    if (cmd != AESDCHAR_IOCSEEKTO)
        return -ENOTTY;

    /* Copy parameters from userspace */
    if (copy_from_user(&seekto, (const void __user *)arg, sizeof(seekto)))
        return -EFAULT;

    write_cmd        = seekto.write_cmd;
    write_cmd_offset = seekto.write_cmd_offset;

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    /* How many valid commands (entries) do we have? */
    if (dev->buffer.full)
        entries = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    else
        entries = dev->buffer.in_offs;

    if (entries == 0 || write_cmd >= entries) {
        mutex_unlock(&dev->lock);
        return -EINVAL;
    }

    /* Sum sizes of all commands before the requested one */
    for (i = 0; i < write_cmd; i++) {
        uint8_t phys = (dev->buffer.out_offs + i) %
                       AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
        entry = &dev->buffer.entry[phys];
        cumulative += entry->size;
    }

    /* Now handle the requested command itself */
    {
        uint8_t phys = (dev->buffer.out_offs + write_cmd) %
                       AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
        entry = &dev->buffer.entry[phys];

        if (write_cmd_offset >= entry->size) {
            mutex_unlock(&dev->lock);
            return -EINVAL;
        }

        cumulative += write_cmd_offset;
    }

    new_pos = (loff_t)cumulative;
    filp->f_pos = new_pos;
    mutex_unlock(&dev->lock);

    return new_pos;
}

static const struct file_operations aesd_fops = {
    .owner          = THIS_MODULE,
    .open           = aesd_open,
    .release        = aesd_release,
    .read           = aesd_read,
    .write          = aesd_write,
    .llseek         = aesd_llseek,
    .unlocked_ioctl = aesd_unlocked_ioctl,
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
    aesd_circular_buffer_init(&aesd_device.buffer);
    mutex_init(&aesd_device.lock);

    aesd_device.partial_buf      = NULL;
    aesd_device.partial_size     = 0;

    result = aesd_setup_cdev(&aesd_device);
    if (result) {
        unregister_chrdev_region(dev, 1);
    }

    return result;
}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);
    uint8_t index;
    struct aesd_buffer_entry *entry;

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index) {
        if (entry->buffptr)
            kfree(entry->buffptr);
    }
    if (aesd_device.partial_buf)
        kfree(aesd_device.partial_buf);
    aesd_device.partial_buf      = NULL;
    aesd_device.partial_size     = 0;

    mutex_destroy(&aesd_device.lock);

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);