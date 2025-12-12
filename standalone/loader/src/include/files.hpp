#pragma once

#include <dirent.h>

#include <functional>
#include <string>

void file_readline(bool trim, FILE *fp, const std::function<bool(std::string_view)> &fn);
void file_readline(bool trim, const char *file, const std::function<bool(std::string_view)> &fn);
void file_readline(const char *file, const std::function<bool(std::string_view)> &fn);

using sFILE = std::unique_ptr<FILE, decltype(&fclose)>;
using sDIR = std::unique_ptr<DIR, decltype(&closedir)>;
sDIR make_dir(DIR *dp);
sFILE make_file(FILE *fp);

static inline sDIR open_dir(const char *path) { return make_dir(opendir(path)); }

static inline sDIR xopen_dir(const char *path) { return make_dir(opendir(path)); }

static inline sDIR xopen_dir(int dirfd) { return make_dir(fdopendir(dirfd)); }

static inline sFILE open_file(const char *path, const char *mode) {
    return make_file(fopen(path, mode));
}

static inline sFILE xopen_file(const char *path, const char *mode) {
    return make_file(fopen(path, mode));
}

static inline sFILE xopen_file(int fd, const char *mode) { return make_file(fdopen(fd, mode)); }
