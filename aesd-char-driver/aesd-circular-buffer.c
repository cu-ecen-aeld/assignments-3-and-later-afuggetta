/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(
        struct aesd_circular_buffer *buffer,
        size_t char_offset,
        size_t *entry_offset_byte_rtn)
{
    uint8_t entries;
    uint8_t read_idx;
    uint8_t i;

    if (!buffer)
        return NULL;

    /* How many valid entries do we have? */
    if (buffer->full)
    {
        entries = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    } else
    {
        entries= (buffer->in_offs + AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - buffer->out_offs) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }

    if (entries == 0)
        return NULL; /* Buffer empty */

    read_idx  = buffer->out_offs;
    size_t total_size = 0;
    // now I need to iterate through the entries
    for (i = 0; i < entries; i++) {
        size_t current_size = buffer->entry[read_idx].size;

        if (char_offset < total_size + current_size) {
            /* Offset falls within this entry */
            if (entry_offset_byte_rtn)
                *entry_offset_byte_rtn = char_offset - total_size;
            return &buffer->entry[read_idx];
        }

        total_size += current_size;
        read_idx = (read_idx + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }

    /* char_offset beyond all data */
    return NULL;
}


/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
void aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    /**
    * TODO: implement per description
    */
    if (!buffer || !add_entry)
        return;

    /* If already full, we're overwriting the oldest entry */
    if (buffer->full) {
        buffer->out_offs =
            (buffer->out_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }

    /* Store new entry at in_offs */
    buffer->entry[buffer->in_offs] = *add_entry;
    
    buffer->in_offs =
        (buffer->in_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

    /* If in and out collide, buffer is now full */
    buffer->full = (buffer->in_offs == buffer->out_offs);
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    if (!buffer) return;
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}