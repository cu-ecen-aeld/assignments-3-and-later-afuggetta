#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"

void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer, 0, sizeof(struct aesd_circular_buffer));
}

/**
 * Return the entry corresponding to char_offset into the concatenation
 * of all entries, and set *entry_offset_byte_rtn to the offset within that
 * entry.  Returns NULL if char_offset is past the end of data.
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(
        struct aesd_circular_buffer *buffer,
        size_t char_offset,
        size_t *entry_offset_byte_rtn)
{
    uint8_t index;
    uint8_t entries;
    size_t  remaining;
    struct aesd_buffer_entry *entry;

    if (!buffer)
        return NULL;

    /* How many valid entries do we have? */
    if (buffer->full) {
        entries = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    } else {
        entries = buffer->in_offs;
    }

    if (entries == 0)
        return NULL; /* empty buffer */

    index     = buffer->out_offs; /* oldest entry */
    remaining = char_offset;

    while (entries--) {
        entry = &buffer->entry[index];

        if (remaining < entry->size) {
            if (entry_offset_byte_rtn)
                *entry_offset_byte_rtn = remaining;
            return entry;
        }

        /* Skip over this entry */
        remaining -= entry->size;
        index = (index + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }

    return NULL;
}

/**
 * Adds entry @param add_entry to @param buffer in the location specified in
 * buffer->in_offs. If the buffer was already full, overwrites the oldest
 * entry and advances buffer->out_offs.
 * Any memory referenced in @param add_entry must have lifetime managed
 * by the caller.
 */
void aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer,
                                    const struct aesd_buffer_entry *add_entry)
{
    if (!buffer || !add_entry)
        return;

    /* Overwrite the slot at in_offs */
    buffer->entry[buffer->in_offs] = *add_entry;

    if (buffer->full) {
        /* Move the oldest forward */
        buffer->out_offs = (buffer->out_offs + 1) %
                           AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }

    buffer->in_offs = (buffer->in_offs + 1) %
                      AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

    /* If in_offs wrapped around to out_offs, we are now full */
    buffer->full = (buffer->in_offs == buffer->out_offs);
}
