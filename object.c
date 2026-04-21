// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── IMPLEMENTED ─────────────────────────────────────────────────────────────

// Write an object to the store.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    const char *type_str = "";
    if (type == OBJ_BLOB) type_str = "blob";
    else if (type == OBJ_TREE) type_str = "tree";
    else if (type == OBJ_COMMIT) type_str = "commit";
    else return -1;

    // 1. Build the full object: header ("<type> <size>\0") + data
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len) + 1; 
    
    size_t full_len = header_len + len;
    unsigned char *full_data = malloc(full_len);
    if (!full_data) return -1;

    memcpy(full_data, header, header_len);
    memcpy(full_data + header_len, data, len);

    // 2. Compute SHA-256 hash of the FULL object
    compute_hash(full_data, full_len, id_out);

    // 3. Deduplication check
    if (object_exists(id_out)) {
        free(full_data);
        return 0; 
    }

    // 4. Create shard directory (.pes/objects/XX/)
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);
    char dir_path[512];
    snprintf(dir_path, sizeof(dir_path), "%s/%.2s", OBJECTS_DIR, hex);
    mkdir(dir_path, 0755); 

    // 5. Write to a temporary file in the same shard directory
    char temp_path[512];
    snprintf(temp_path, sizeof(temp_path), "%s/temp_XXXXXX", dir_path);
    int fd = mkstemp(temp_path);
    if (fd < 0) {
        free(full_data);
        return -1;
    }

    if (write(fd, full_data, full_len) != (ssize_t)full_len) {
        close(fd);
        unlink(temp_path);
        free(full_data);
        return -1;
    }

    // 6. fsync the temporary file
    fsync(fd);
    close(fd);

    // 7. Atomically rename() the temp file to the final path
    char final_path[512];
    object_path(id_out, final_path, sizeof(final_path));
    if (rename(temp_path, final_path) != 0) {
        unlink(temp_path);
        free(full_data);
        return -1;
    }

    // 8. Open and fsync() the shard directory to persist the rename
    int dir_fd = open(dir_path, O_RDONLY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }

    free(full_data);
    return 0; 
}

// Read an object from the store.
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    // 1. Build the file path
    char path[512];
    object_path(id, path, sizeof(path));

    // 2. Open and read the entire file
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long full_len = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *full_data = malloc(full_len);
    if (!full_data) {
        fclose(f);
        return -1;
    }

    if (fread(full_data, 1, full_len, f) != (size_t)full_len) {
        free(full_data);
        fclose(f);
        return -1;
    }
    fclose(f);

    // 4. Verify integrity: recompute SHA-256 and compare
    ObjectID computed_id;
    compute_hash(full_data, full_len, &computed_id);
    if (memcmp(id->hash, computed_id.hash, HASH_SIZE) != 0) {
        free(full_data);
        return -1; // Hash mismatch / corrupted data
    }

    // 3. Parse the header to extract the type string and size
    char *null_byte = memchr(full_data, '\0', full_len);
    if (!null_byte) {
        free(full_data);
        return -1;
    }

    char type_str[16];
    size_t size;
    if (sscanf((char *)full_data, "%15s %zu", type_str, &size) != 2) {
        free(full_data);
        return -1;
    }

    // 5. Set *type_out to the parsed ObjectType
    if (strcmp(type_str, "blob") == 0) {
        *type_out = OBJ_BLOB;
    } else if (strcmp(type_str, "tree") == 0) {
        *type_out = OBJ_TREE;
    } else if (strcmp(type_str, "commit") == 0) {
        *type_out = OBJ_COMMIT;
    } else {
        free(full_data);
        return -1;
    }

    // 6. Allocate buffer, copy data portion, and set output variables
    *len_out = size;
    *data_out = malloc(size);
    if (!*data_out) {
        free(full_data);
        return -1;
    }

    size_t header_len = (null_byte - (char *)full_data) + 1;
    memcpy(*data_out, full_data + header_len, size);

    free(full_data);
    return 0;
}
