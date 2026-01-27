/*
 * This file is part of Sui.
 *
 * Sui is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Sui is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Sui.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2021-2026 Sui Contributors
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_STRING_LEN 16384

int find_and_replace_string(const char* filename, const char* old_str, const char* new_str) {
    FILE* fp = fopen(filename, "rb+");
    if (!fp) {
        perror("Error opening file");
        return -1;
    }

    // Get file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Read entire file into memory
    char* file_content = (char*)malloc(file_size);
    if (!file_content) {
        fclose(fp);
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    if (fread(file_content, 1, file_size, fp) != file_size) {
        free(file_content);
        fclose(fp);
        fprintf(stderr, "Error reading file\n");
        return -1;
    }

    // Find the old string
    char* found_pos = (char*)memmem(file_content, file_size, old_str, strlen(old_str));
    if (!found_pos) {
        free(file_content);
        fclose(fp);
        fprintf(stderr, "Old string not found in file\n");
        return -1;
    }

    long offset = found_pos - file_content;
    size_t old_len = strlen(old_str);
    size_t new_len = strlen(new_str);

    if (new_len > old_len) {
        free(file_content);
        fclose(fp);
        fprintf(stderr, "New string is longer than old string (%zu > %zu)\n", new_len, old_len);
        return -1;
    }

    // Write changes
    fseek(fp, offset, SEEK_SET);
    if (fwrite(new_str, 1, new_len, fp) != new_len) {
        free(file_content);
        fclose(fp);
        fprintf(stderr, "Error writing new string\n");
        return -1;
    }

    // Pad with null bytes if new string is shorter
    if (new_len < old_len) {
        size_t padding = old_len - new_len;
        char zero = 0;
        for (size_t i = 0; i < padding; i++) {
            if (fwrite(&zero, 1, 1, fp) != 1) {
                free(file_content);
                fclose(fp);
                fprintf(stderr, "Error writing padding\n");
                return -1;
            }
        }
    }

    free(file_content);
    fclose(fp);
    printf("Successfully replaced string at offset 0x%lx\n", offset);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <filename> <old_string> <new_string>\n", argv[0]);
        return 1;
    }

    const char* filename = argv[1];
    const char* old_str = argv[2];
    const char* new_str = argv[3];

    if (strlen(old_str) == 0) {
        fprintf(stderr, "Error: Old string cannot be empty\n");
        return 1;
    }

    if (strlen(old_str) > MAX_STRING_LEN || strlen(new_str) > MAX_STRING_LEN) {
        fprintf(stderr, "Error: Strings too long (max %d characters)\n", MAX_STRING_LEN);
        return 1;
    }

    return find_and_replace_string(filename, old_str, new_str) ? 1 : 0;
}