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

    if(mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->buffer);
    if(!entry || entry->size == 0)
    {
        total_read = 0;
        goto out_unlock;
    }

    if (copy_to_user(buf, entry->buffptr + entry_off, to_copy)) {
        if (total_read == 0)
            total_read = -EFAULT;
        goto out_unlock;
    }

    *f_pos += to_copy;
    total_read = to_copy;

out_unlock:
    mutex_unlock(&dev->lock);
    return total_read;
}

static ssize_t aesd_write(struct file *filp, const char __user *buf,
                          size_t count, loff_t *f_pos)
{
    struct aesd_dev *dev = filp->private_data;
    ssize_t retval = count;
    int err;
    char *newline;
    size_t cmd_len;
    
    struct aesd_buffer_entry *slot_to_free;

    if (!dev)
        return -EFAULT;

    if(mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    size_t needed;
    char *newbuf;

    needed = dev->partial_size + count;

    newbuf = kmalloc(needed, GFP_KERNEL);
    if (!newbuf)
    {
        retval = -ENOMEM;
        goto out_unlock;
    }

    if (dev->partial_buf)
        memcpy(newbuf, dev->partial_buf, dev->partial_size);

    if (copy_from_user(newbuf + dev->partial_size, buf, count))
    {
        retval = -EFAULT;
        goto out_unlock;
    }

    for (size_t i = 0; i < needed; i++) {
        if (newbuf[i] != '\n')
            continue;

        struct aesd_buffer_entry new_entry;
        new_entry.size = i + 1;
        new_entry.buffptr = kmalloc(new_entry.size, GFP_KERNEL);
        if (!new_entry.buffptr) {
            retval = -ENOMEM;
            goto out_unlock;
        }

        memcpy((char *)new_entry.buffptr, newbuf, new_entry.size);

        if (dev->buffer.full) {
            kfree((void *)dev->buffer.entry[dev->buffer.out_offs].buffptr);
        }

        aesd_circular_buffer_add_entry(&dev->circbuf, &new_entry);

        dev->partial_size = needed - (i + 1);
        if (dev->partial_size > 0)
        {
            dev->partial_buf = kmalloc(dev->partial_size, GP_KERNEL);
            if (!dev->partial_buf)
            {
                retval = -ENOMEM;
                goto out_unlock;
            }
            memcpy(dev->partial_buf, newbuf + i + 1, dev->partial_size);
        } else
        {
            dev->partial_buf = NULL;
            dev->partial_size - 0;
        }

        retval = count;
        goto out_unlock;
    }

    kfree(dev->partial_buf);
    dev->partial_buf = kmalloc(needed, GP_KERNEL);
    memcpy(dev->partial_buf, newbuf, needed);
    retval = count;

out_unlock:
    if (newbuf)
        kfree(newbuf);
    mutex_unlock(&dev->lock);
    return retval;
}

static const struct file_operations aesd_fops = {
    .owner   = THIS_MODULE,
    .open    = aesd_open,
    .release = aesd_release,
    .read    = aesd_read,
    .write   = aesd_write,
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
    aesd_circular_buffer_init(&aesd_device.circbuf);
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
    aesd_device.partial_capacity = 0;

    mutex_destroy(&aesd_device.lock);

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);