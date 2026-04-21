// tree.c — Tree object serialization and construction
//
// PROVIDED functions: get_file_mode, tree_parse, tree_serialize
// TODO functions:     tree_from_index

#include "tree.h"
#include "pes.h"
#include "index.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

// Forward declaration for the object store since it's not in the headers
extern int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE      0100644
#define MODE_EXEC      0100755
#define MODE_DIR       0040000

// ─── PROVIDED ───────────────────────────────────────────────────────────────

// Determine the object mode for a filesystem path.
uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;

    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

// Parse binary tree data into a Tree struct safely.
int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1; 

        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);

        ptr = space + 1; 

        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1; 

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0'; 

        ptr = null_byte + 1; 

        if (ptr + HASH_SIZE > end) return -1; 
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    size_t max_size = tree->count * 296; 
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];
        
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1; 
        
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── IMPLEMENTED ─────────────────────────────────────────────────────────────

// Temporary weak symbol to fix the Makefile's linker bug for Phase 2.
// When Phase 3 links the real index_load, this dummy will be safely ignored.
__attribute__((weak)) int index_load(Index *idx) {
    (void)idx;
    return -1;
}

// Helper function to recursively build tree objects from index entries
static int build_tree_recursive(IndexEntry *entries, int count, int path_offset, ObjectID *out_hash) {
    Tree tree;
    tree.count = 0;
    int i = 0;

    while (i < count) {
        const char *current_path = entries[i].path + path_offset;
        char *slash = strchr(current_path, '/');

        if (!slash) {
            TreeEntry *te = &tree.entries[tree.count++];
            strcpy(te->name, current_path);
            te->mode = entries[i].mode;
            te->hash = entries[i].hash;
            i++;
        } else {
            int dir_len = slash - current_path;
            char dir_name[256];
            strncpy(dir_name, current_path, dir_len);
            dir_name[dir_len] = '\0';

            int j = i;
            while (j < count) {
                const char *check_path = entries[j].path + path_offset;
                if (strncmp(check_path, dir_name, dir_len) == 0 && check_path[dir_len] == '/') {
                    j++;
                } else {
                    break;
                }
            }

            ObjectID sub_hash;
            if (build_tree_recursive(&entries[i], j - i, path_offset + dir_len + 1, &sub_hash) != 0) {
                return -1;
            }

            TreeEntry *te = &tree.entries[tree.count++];
            strcpy(te->name, dir_name);
            te->mode = MODE_DIR;
            te->hash = sub_hash;

            i = j; 
        }
    }

    void *data = NULL;
    size_t len = 0;
    if (tree_serialize(&tree, &data, &len) != 0) {
        return -1;
    }

    int rc = object_write(OBJ_TREE, data, len, out_hash);
    free(data);
    return rc;
}

// Build a tree hierarchy from the current index and write all tree
// objects to the object store.
int tree_from_index(ObjectID *id_out) {
    Index idx;
    
    if (index_load(&idx) != 0) {
        return -1;
    }

    if (idx.count == 0) {
        Tree tree;
        tree.count = 0;
        void *data;
        size_t len;
        tree_serialize(&tree, &data, &len);
        int rc = object_write(OBJ_TREE, data, len, id_out);
        free(data);
        return rc;
    }

    return build_tree_recursive(idx.entries, idx.count, 0, id_out);
}