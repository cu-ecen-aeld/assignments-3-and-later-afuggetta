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

    if (count == 0)
        return 0;

    mutex_lock(&dev->lock);

    offset = *f_pos;

    while (count > 0) {
        entry = aesd_circular_buffer_find_entry_offset_for_fpos(
                    &dev->circbuf, offset, &entry_off);
        if (!entry)
            break; /* no more data => EOF */

        to_copy = entry->size - entry_off;
        if (to_copy > count)
            to_copy = count;

        if (copy_to_user(buf, entry->buffptr + entry_off, to_copy)) {
            if (total_read == 0)
                total_read = -EFAULT;
            goto out_unlock;
        }

        buf        += to_copy;
        count      -= to_copy;
        offset     += to_copy;
        total_read += to_copy;
    }

    *f_pos = offset;

out_unlock:
    mutex_unlock(&dev->lock);
    return total_read;
}


static int aesd_append_partial(struct aesd_dev *dev,
                               const char __user *buf,
                               size_t count)
{
    size_t needed;
    char *newbuf;

    if (!dev || !buf || count == 0)
        return 0;

    needed = dev->partial_size + count;

    if (needed > dev->partial_capacity) {
        size_t new_cap = dev->partial_capacity ?
                         dev->partial_capacity * 2 :
                         needed;
        if (new_cap < needed)
            new_cap = needed;

        newbuf = kmalloc(new_cap, GFP_KERNEL);
        if (!newbuf)
            return -ENOMEM;

        if (dev->partial_buf && dev->partial_size)
            memcpy(newbuf, dev->partial_buf, dev->partial_size);

        kfree(dev->partial_buf);
        dev->partial_buf      = newbuf;
        dev->partial_capacity = new_cap;
    }

    if (copy_from_user(dev->partial_buf + dev->partial_size, buf, count))
        return -EFAULT;

    dev->partial_size += count;

    return 0;
}

static ssize_t aesd_write(struct file *filp, const char __user *buf,
                          size_t count, loff_t *f_pos)
{
    struct aesd_dev *dev = filp->private_data;
    ssize_t retval = count;
    int err;
    char *newline;
    size_t cmd_len;
    struct aesd_buffer_entry new_entry;
    struct aesd_buffer_entry *slot_to_free;

    if (!dev)
        return -EFAULT;

    mutex_lock(&dev->lock);

    err = aesd_append_partial(dev, buf, count);
    if (err < 0) {
        retval = err;
        goto out_unlock;
    }

    while (1) {
        newline = memchr(dev->partial_buf, '\n', dev->partial_size);
        if (!newline)
            break; 

        cmd_len = (newline - dev->partial_buf) + 1;

        new_entry.buffptr = kmalloc(cmd_len, GFP_KERNEL);
        if (!new_entry.buffptr) {
            retval = -ENOMEM;
            goto out_unlock;
        }

        memcpy((char *)new_entry.buffptr, dev->partial_buf, cmd_len);
        new_entry.size = cmd_len;

        if (dev->circbuf.full) {
            slot_to_free = &dev->circbuf.entry[dev->circbuf.in_offs];
            if (slot_to_free->buffptr) {
                kfree(slot_to_free->buffptr);
                slot_to_free->buffptr = NULL;
                slot_to_free->size = 0;
            }
        }

        aesd_circular_buffer_add_entry(&dev->circbuf, &new_entry);

        memmove(dev->partial_buf,
                dev->partial_buf + cmd_len,
                dev->partial_size - cmd_len);
        dev->partial_size -= cmd_len;
    }

out_unlock:
    mutex_unlock(&dev->lock);
    return retval;
}

static const struct file_operations aesd_fops = {
    .owner   = THIS_MODULE,
    .open    = aesd_open,
    .release = aesd_release,
    .read    = aesd_read,
    .write   = aesd_write,
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

    aesd_circular_buffer_init(&aesd_device.circbuf);

    aesd_device.partial_buf      = NULL;
    aesd_device.partial_size     = 0;
    aesd_device.partial_capacity = 0;

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
    for (index = 0; index < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; index++) {
        entry = &aesd_device.circbuf.entry[index];
        if (entry->buffptr) {
            kfree(entry->buffptr);
            entry->buffptr = NULL;
            entry->size = 0;
        }
    }
    kfree(aesd_device.partial_buf);
    aesd_device.partial_buf      = NULL;
    aesd_device.partial_size     = 0;
    aesd_device.partial_capacity = 0;

    mutex_destroy(&aesd_device.lock);

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);