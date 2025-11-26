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

const uint8_t MAX = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
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

struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    uint8_t entries_in_use; 
    uint8_t idx = buffer->out_offs;

  
    if (!buffer->full && (buffer->in_offs == buffer->out_offs))
        return NULL; //as the buffer is empty and nothing to check with the offset


    // To find out the entries currently in the buffer

    if (buffer->full) {
        entries_in_use = MAX;  
    } else {
       entries_in_use = ((buffer->in_offs + MAX - buffer->out_offs) % MAX);
    }

    size_t total_seen = 0; 
    
    for (uint8_t i = 0; i < entries_in_use; i++) {

        // Getting the current entry pointer
        struct aesd_buffer_entry *entry = &buffer->entry[idx];

        //char_offset falls inside this entry
        if (char_offset < total_seen + entry->size) {
            *entry_offset_byte_rtn = char_offset - total_seen; // To calculate position within this entry
            return entry;
        }

        
        total_seen += entry->size;
        idx  = ((idx  + 1) % MAX);
    }

   
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
    buffer->entry[buffer->in_offs] = *add_entry; 

    // Moving the out_offs forward so oldest entry always points to the true oldest.
    if (buffer->full) {
        buffer->out_offs = ((buffer->out_offs + 1) % MAX);
    }

    buffer->in_offs = ((buffer->in_offs + 1) % MAX);
    
    if (buffer->in_offs == buffer->out_offs)
        buffer->full = true;
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}