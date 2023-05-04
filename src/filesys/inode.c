#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DIRECTS_SIZE 124

#define INDIRECT_SIZE 128

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  block_sector_t directs[124];  /* Array of 124 direct pointers. */
  block_sector_t indirect;      /* Singly indirect pointer. */
  block_sector_t dbl_indirect;  /* Doublely-indirect pointer. */
  off_t length;         /* File size in bytes. */
  unsigned magic;       /* Magic number. */
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* In-memory inode. */
struct inode {
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
// static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
//   ASSERT(inode != NULL);
//   if (pos < inode->data.length)
//     return inode->data.start + pos / BLOCK_SECTOR_SIZE;
//   else
//     return -1;
// }

static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  // https://edstem.org/us/courses/33980/discussion/2905210?comment=6916229 stack memcpy strat, need to change to inplace once buffer cache is introduced
  struct inode_disk disk_inode;
  uint8_t buffer[BLOCK_SECTOR_SIZE]; // array of 512 bytes
  block_read(fs_device, inode->sector, &buffer);
  memcpy(&disk_inode, &buffer, BLOCK_SECTOR_SIZE); // inode_disk with its direct ... pointers, but in memory!
  
  if (pos < disk_inode.length) {
    if (pos < 124 * BLOCK_SECTOR_SIZE) {
      // the position we want to read at is in one of the direct pointers
      block_sector_t sector_id = disk_inode.directs[pos / BLOCK_SECTOR_SIZE];
      return sector_id;
    } else if (pos < 124 * BLOCK_SECTOR_SIZE + BLOCK_SECTOR_SIZE * BLOCK_SECTOR_SIZE / 4) {
      // the position we want to read at has to go through the indirect pointer
      block_sector_t indirect_pointers[BLOCK_SECTOR_SIZE / 4];
      block_read(fs_device, &disk_inode->indirect, &indirect_pointers);
      // then find the right pointer out of the 128 (512 block size / 4 bytes per sector pointer) that the indirect references
      off_t indirect_pos = pos - 124 * BLOCK_SECTOR_SIZE; // account for passing the direct pointers
      block_sector_t sector_id = indirect_pointers[indirect_pos / BLOCK_SECTOR_SIZE];
      return sector_id;
    } else {
      // doubly indirect pointer
      block_sector_t dbl_indirect_pointers[BLOCK_SECTOR_SIZE / 4];
      block_read(fs_device, &disk_inode->dbl_indirect, &dbl_indirect_pointers);
      // then find the right indirect pointer out of the 128 (512 block size / 4 bytes per sector pointer) that the dbl indirect references
      off_t new_pos = pos - (124 + BLOCK_SECTOR_SIZE / 4) * BLOCK_SECTOR_SIZE; // account for passing all direct pointers and the indirect pointer
      off_t dbl_index = new_pos / (BLOCK_SECTOR_SIZE * BLOCK_SECTOR_SIZE / 4);
      
      block_sector_t indirect_id = dbl_indirect_pointers[dbl_index];

      // read the indirect pointer we identified
      block_sector_t indirect_pointers[BLOCK_SECTOR_SIZE / 4];
      block_read(fs_device, indirect_id, &indirect_pointers);
      
      off_t indirect_pos = new_pos - dbl_index * BLOCK_SECTOR_SIZE; // account for passing over some indirect pointers when indexing into our doubly indirect pointer

      block_sector_t sector_id = indirect_pointers[indirect_pos / BLOCK_SECTOR_SIZE];
      return sector_id;
    }
  } else {
    return -1;
  }
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void) { list_init(&open_inodes); }

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length) {
  struct inode_disk* disk_inode = NULL;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode != NULL) {
    size_t sectors = bytes_to_sectors(length);
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;
    if (free_map_allocate(sectors, &disk_inode->start)) {
      block_write(fs_device, sector, disk_inode);
      if (sectors > 0) {
        static char zeros[BLOCK_SECTOR_SIZE];
        size_t i;

        for (i = 0; i < sectors; i++)
          block_write(fs_device, disk_inode->start + i, zeros);
      }
      success = true;
    }
    free(disk_inode);
  }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;

  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  block_read(fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      free_map_release(inode->sector, 1);
      free_map_release(inode->data.start, bytes_to_sectors(inode->data.length));
    }

    free(inode);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t* bounce = NULL;

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Read full sector directly into caller's buffer. */
      block_read(fs_device, sector_idx, buffer + bytes_read);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }
      block_read(fs_device, sector_idx, bounce);
      memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  free(bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t* bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Write full sector directly to disk. */
      block_write(fs_device, sector_idx, buffer + bytes_written);
    } else {
      /* We need a bounce buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }

      /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
      if (sector_ofs > 0 || chunk_size < sector_left)
        block_read(fs_device, sector_idx, bounce);
      else
        memset(bounce, 0, BLOCK_SECTOR_SIZE);
      memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      block_write(fs_device, sector_idx, bounce);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  free(bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) { return inode->data.length; }

bool inode_resize(struct inode_disk* id, off_t size) {
  block_sector_t sector;
  /* Handle direct pointers. */
  for (int i = 0; i < DIRECTS_SIZE; i++) {
    if (size <= BLOCK_SECTOR_SIZE * i && id->directs[i] != 0) {
      /* Shrink. */
      //block_free(id->directs[i]);
      id->directs[i] = 0;
    } else if (size > BLOCK_SECTOR_SIZE * i && id->directs[i] == 0) {
      /* Grow. */
      //id->directs[i] = block_allocate();
    }
  }

  //sanity check needed (check the bool for allocate)
  indirect_block_write(id->indirect, size - DIRECTS_SIZE * BLOCK_SECTOR_SIZE);

  /* Get double indirect pointers*/
  block_sector_t dbl_indirect_block[INDIRECT_SIZE];
  memset(dbl_indirect_block, 0, 512);
  if (id->dbl_indirect == 0) {
    /* Allocate indirect block. */
    //id->dbl_indirect = block_allocate();
  } else {
    /* Read in indirect block. */
    block_read(fs_device, id->dbl_indirect, dbl_indirect_block);
  }

  /* Handle double indirect pointers. */
  for (int j = 0; j < INDIRECT_SIZE; j++){
    /* Shrink. */
    if (size <= (DIRECTS_SIZE + INDIRECT_SIZE + j) * BLOCK_SECTOR_SIZE && dbl_indirect_block[j] != 0) {
      //indirect_block_free(dbl_indirect_block[j]);
      dbl_indirect_block[j] = 0;
    } else if (size > (DIRECTS_SIZE + INDIRECT_SIZE + j) * BLOCK_SECTOR_SIZE && dbl_indirect_block[j] == 0) {
      /* Grow. */
      //dbl_indirect_block[j] = block_allocate();
      indirect_block_write(dbl_indirect_block[j],
                           size - (DIRECTS_SIZE + INDIRECT_SIZE + j) * BLOCK_SECTOR_SIZE);
    }
  }

  /* We shrank the inode such that dbl_indirect pointers are not required. */
  if (size <= (DIRECTS_SIZE + INDIRECT_SIZE) * BLOCK_SECTOR_SIZE) {
    //block_free(id->dbl_indirect);
    id->dbl_indirect = 0;
  }
  /* Write the updates to the dbl_indirect block back to disk. */
  else {
    block_write(fs_device, id->dbl_indirect, dbl_indirect_block);
  }

  id->length = size;
  return true;
}

bool indirect_block_write(block_sector_t indirect, off_t size) {
  /* Get indirect pointer block. */
  block_sector_t indirect_block[INDIRECT_SIZE];
  memset(indirect_block, 0, 512);
  if (indirect == 0) {
    /* Allocate indirect block. */
    //indirect = block_allocate();
  } else {
    /* Read in indirect block. */
    block_read(fs_device, indirect, indirect_block);
  }

  /* Handle indirect pointers. */
  for (int i = 0; i < INDIRECT_SIZE; i++) {
    if (size <= i * BLOCK_SECTOR_SIZE && indirect_block[i] != 0) {
      /* Shrink. */
      //block_free(indirect_block[i]);
      indirect_block[i] = 0;
    } else if (size > i * BLOCK_SECTOR_SIZE && indirect_block[i] == 0) {
      /* Grow. */
      //indirect_block[i] = block_allocate();
    }
  }

  /* We shrank the inode such that indirect pointers are not required. */
  if (size <= 0) {
    //block_free(id->indirect);
    indirect = 0;
  }
  /* Write the updates to the indirect block back to disk. */
  else {
    block_write(fs_device, indirect, indirect_block);
  }
}