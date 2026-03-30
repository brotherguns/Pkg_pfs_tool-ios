/*
 * util_ios.c
 *
 * Drop-in replacement for pkg_pfs_tool/src/util.c on iOS.
 * Identical to the original EXCEPT that error() calls pkg_ios_abort()
 * instead of exit(1), so a failed extraction doesn't kill the app.
 *
 * Compile this file instead of (not alongside) the original util.c.
 */

#include "util.h"
#include "pkg_ios_abort.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>

void info(const char* fmt, ...) {
    char buffer[1024];
    va_list args;
    assert(fmt != NULL);
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    fprintf(stdout, "%s\n", buffer);
}

void warning(const char* fmt, ...) {
    char buffer[1024];
    va_list args;
    assert(fmt != NULL);
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    fprintf(stderr, "WARNING: %s\n", buffer);
    pkg_ios_log_warning(buffer);  /* capture for error reporting */
}

/* CHANGED: longjmp instead of exit(1) */
void error(const char* fmt, ...) {
    char buffer[1024];
    va_list args;
    assert(fmt != NULL);
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    fprintf(stderr, "ERROR: %s\n", buffer);
    pkg_ios_abort(buffer);
    /* If abort returns somehow (it won't), prevent UB */
    __builtin_unreachable();
}

int is_exists(const char* path) {
    struct stat info;
    assert(path != NULL);
    return stat(path, &info) == 0;
}

int is_file(const char* path) {
    struct stat info;
    assert(path != NULL);
    if (stat(path, &info) < 0) return 0;
    return S_ISREG(info.st_mode);
}

int is_directory(const char* path) {
    struct stat info;
    assert(path != NULL);
    if (stat(path, &info) < 0) return 0;
    return S_ISDIR(info.st_mode);
}

int is_drive_letter(const char* path) {
    assert(path != NULL);
    return 0; /* N/A on iOS */
}

int is_readable(const char* path) {
    assert(path != NULL);
    return access(path, R_OK) == 0;
}

int is_writeable(const char* path) {
    assert(path != NULL);
    return access(path, W_OK) == 0;
}

int has_magic(void* source, size_t source_size, const void* magic, size_t magic_size) {
    assert(source != NULL);
    assert(magic != NULL);
    if (source_size < magic_size) return 0;
    return memcmp(source, magic, magic_size) == 0;
}

int file_has_magic(const char* path, const void* magic, size_t magic_size) {
    FILE* fp = NULL;
    void* tmp = NULL;
    int status = 0;
    assert(path != NULL);
    assert(magic != NULL);
    fp = fopen(path, "rb");
    if (!fp) goto done;
    tmp = malloc(magic_size);
    if (!tmp) goto done;
    memset(tmp, 0, magic_size);
    if (fread(tmp, 1, magic_size, fp) != magic_size) goto done;
    status = has_magic(tmp, magic_size, magic, magic_size);
done:
    if (tmp) free(tmp);
    if (fp)  fclose(fp);
    return status;
}

uint64_t get_file_size(const char* path) {
    struct stat info;
    assert(path != NULL);
    if (stat(path, &info) < 0) return (uint64_t)-1;
    return (uint64_t)info.st_size;
}

int make_directory(const char* path, int mode) {
    assert(path != NULL);
    return mkdir(path, (mode_t)mode) == 0;
}

int make_directories(const char* path, int mode) {
    char directory[PATH_MAX];
    const char* part;
    const char* separator;
    size_t part_length;
    assert(path != NULL);
    part = path;
    while (*part != '\0') {
        separator = path_get_separator(part);
        if (*separator != '\0')
            part_length = separator - path;
        else
            part_length = strlen(path);
        if (part_length > sizeof(directory) - 1) return 0;
        if (part_length != 0) {
            memset(directory, 0, sizeof(directory));
            strncpy(directory, path, part_length);
            if (!is_directory(directory)) {
                if (!is_exists(directory)) {
                    if (!make_directory(directory, mode)) {
                        warning("Unable to create directory: %s", directory);
                        return 0;
                    }
                } else {
                    warning("Unable to create directory (path exists): %s", directory);
                    return 0;
                }
            }
        }
        part = path_skip_separator(separator);
    }
    return 1;
}

static char* join_path(const char* parent, const char* child) {
    char* buf = NULL;
    char* p;
    size_t parent_len = (parent && *parent) ? strlen(parent) : 0;
    size_t child_len  = (child  && *child)  ? strlen(child)  : 0;
    size_t len = parent_len + (parent_len > 0 && child_len > 0 ? 1 : 0) + child_len;
    p = buf = (char*)malloc(len + 1);
    if (!p) return NULL;
    if (parent_len > 0) { strncpy(p, parent, parent_len); p += parent_len; if (child_len > 0) *p++ = '/'; }
    if (child_len  > 0) { strncpy(p, child,  child_len);  p += child_len; }
    *p = '\0';
    return buf;
}

int list_directory_r_internal(const char* parent_name, const char* name, list_directory_cb cb, void* cb_arg) {
    char* full_name = NULL;
    char* tmp_name  = NULL;
    DIR* dp = NULL;
    struct dirent* entry;
    struct stat stat_buf;
    int status = 0;
    full_name = join_path(parent_name, name);
    if (!full_name) goto error;
    dp = opendir(full_name);
    if (!dp) goto error;
    while ((entry = readdir(dp)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        tmp_name = join_path(full_name, entry->d_name);
        if (!tmp_name) goto error;
        if (stat(tmp_name, &stat_buf) < 0) goto error;
        free(tmp_name); tmp_name = NULL;
        if (cb && (*cb)(cb_arg, full_name, entry->d_name, stat_buf.st_mode) == CB_RESULT_STOP) goto done;
        if (S_ISDIR(stat_buf.st_mode)) list_directory_r_internal(full_name, entry->d_name, cb, cb_arg);
    }
done:
    status = 1;
error:
    if (tmp_name) free(tmp_name);
    if (dp) closedir(dp);
    if (full_name) free(full_name);
    return status;
}

int list_directory_r(const char* directory, list_directory_cb cb, void* cb_arg) {
    return list_directory_r_internal(NULL, directory, cb, cb_arg);
}

int write_to_file(const char* path, const void* data, size_t size, ssize_t* nwritten, int mode) {
    int fd = -1;
    int status = 0;
    ssize_t n;
    assert(path != NULL);
    assert(data != NULL);
    fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, (mode_t)mode);
    if (fd < 0) goto error;
    n = write(fd, data, size);
    if (n < 0) goto error;
    if (nwritten) *nwritten = n;
    status = 1;
error:
    if (fd > 0) close(fd);
    return status;
}

unsigned int ctz_32(uint32_t n)  { return n ? (unsigned int)__builtin_ctz(n)   : (unsigned int)-1; }
unsigned int ctz_64(uint64_t n)  { return n ? (unsigned int)__builtin_ctzll(n) : (unsigned int)-1; }
unsigned int popcnt_32(uint32_t n) { return __builtin_popcount(n); }
unsigned int popcnt_64(uint64_t n) { return __builtin_popcountll(n); }

unsigned int ilog2_32(uint32_t n) {
    return ((unsigned int)(sizeof(n)*8) - (unsigned int)__builtin_clzl((n<<1)-1) - 1);
}
unsigned int ilog2_64(uint64_t n) {
    return ((unsigned int)(sizeof(n)*8) - (unsigned int)__builtin_clzll((n<<1)-1) - 1);
}

ptrdiff_t str_index(const char* s, char ch) {
    char* p;
    assert(s != NULL);
    p = strchr(s, ch);
    return p ? (ptrdiff_t)(p - s) : -1;
}

void strip_trailing_newline(char* s) {
    size_t len;
    assert(s != NULL);
    len = strlen(s);
    if (len && s[len-1] == '\n') s[len-1] = '\0';
}

char* ltrim_ex(char* s, int (*check)(int ch)) {
    size_t start, end;
    assert(s != NULL); assert(check != NULL);
    if (!*s) return s;
    for (start = 0; s[start] && check(s[start]); ++start);
    for (end = start+1; s[end]; ++end);
    memmove(s, s+start, end-start+1);
    return s;
}

char* rtrim_ex(char* s, int (*check)(int ch)) {
    char* end; size_t len;
    assert(s != NULL); assert(check != NULL);
    if (!*s) return s;
    len = strlen(s);
    for (end = &s[len-1]; end >= s && check(*end); --end);
    end[1] = '\0';
    return end >= s ? end : NULL;
}

static int check_space(int ch)  { return isspace(ch); }
static int check_slashes(int ch){ return ch=='/' || ch=='\\'; }

char* ltrim(char* s)         { return ltrim_ex(s, check_space); }
char* rtrim(char* s)         { return rtrim_ex(s, check_space); }
char* rtrim_slashes(char* s) { return rtrim_ex(s, check_slashes); }

int starts_with(const char* h, const char* n) {
    int i;
    assert(h && n);
    for (i=0; h[i]; ++i) if (h[i]!=n[i]) break;
    return n[i]=='\0';
}
int starts_with_nocase(const char* h, const char* n) {
    int i;
    assert(h && n);
    for (i=0; h[i]; ++i) if (tolower(h[i])!=tolower(n[i])) break;
    return n[i]=='\0';
}
int ends_with(const char* h, const char* n) {
    ptrdiff_t diff; int i;
    assert(h && n);
    diff = strlen(h) - strlen(n);
    if (diff < 0) return 0;
    for (i=0; n[i]; ++i) if (n[i]!=h[i+diff]) return 0;
    return 1;
}
int ends_with_nocase(const char* h, const char* n) {
    ptrdiff_t diff; int i;
    assert(h && n);
    diff = strlen(h) - strlen(n);
    if (diff < 0) return 0;
    for (i=0; n[i]; ++i) if (tolower(n[i])!=tolower(h[i+diff])) return 0;
    return 1;
}

const char* path_get_separator(const char* path) {
    const char* p;
    assert(path != NULL);
    if (!*path || *path=='/' || *path=='\\') return path;
    p = path;
    do { p++; } while (*p && *p!='/' && *p!='\\');
    return p;
}
const char* path_skip_separator(const char* path) {
    const char* p;
    assert(path != NULL);
    if (*path!='/' && *path!='\\') return path;
    p = path;
    do { p++; } while (*p=='/' || *p=='\\');
    return p;
}
const char* path_get_file_name(char* file_name, size_t max_size, const char* path) {
    const char* p;
    assert(file_name && path);
    p = strrchr(path, '/');
    if (!p) p = strrchr(path, '\\');
    if (!p) strncpy(file_name, path, max_size);
    else    strncpy(file_name, p+1, max_size);
    return file_name;
}
const char* path_get_directory(char* directory, size_t max_size, const char* path) {
    const char* p; size_t len;
    assert(directory && path);
    p = strrchr(path, '/');
    if (!p) p = strrchr(path, '\\');
    if (!p) { directory[0]='\0'; }
    else { len=p-path; strncpy(directory, path, len<max_size?len:max_size); directory[len<max_size?len:max_size-1]='\0'; }
    return directory;
}
const char* path_slashes_to_backslashes(char* path) {
    size_t i, len; assert(path);
    for (len=strlen(path),i=0;i<len;++i) if (path[i]=='/') path[i]='\\';
    return path;
}
const char* path_backslashes_to_slashes(char* path) {
    size_t i, len; assert(path);
    for (len=strlen(path),i=0;i<len;++i) if (path[i]=='\\') path[i]='/';
    return path;
}

uint64_t x_to_u64(const char* hex) {
    uint64_t result=0; size_t len; int c,t;
    assert(hex);
    len=strlen(hex);
    while (len--) {
        c=*hex++;
        if (c>='0'&&c<='9') t=c-'0';
        else if (c>='a'&&c<='f') t=c-'a'+10;
        else if (c>='A'&&c<='F') t=c-'A'+10;
        else t=0;
        result|=(uint64_t)t<<(len*4);
    }
    return result;
}

uint8_t* x_to_u8_buffer(const char* hex, size_t* size) {
    char tmp[3]={'\0'};
    uint8_t* result=NULL; uint8_t* ptr;
    size_t len=0;
    assert(hex);
    len=strlen(hex);
    if (len%2!=0) goto error;
    result=(uint8_t*)malloc(len);
    if (!result) goto error;
    memset(result,0,len);
    if (size) *size=len/2;
    ptr=result;
    while (len--) { tmp[0]=*hex++; tmp[1]=*hex++; *ptr++=(uint8_t)x_to_u64(tmp); }
    return result;
error:
    if (size) *size=0;
    return NULL;
}

int generate_crypto_random(uint8_t* data, size_t data_size) {
    int fd=-1; size_t offset; ssize_t ret; int status=0;
    assert(data);
    fd=open("/dev/random", O_RDONLY);
    if (fd<0) { warning("Unable to open random device."); goto error; }
    for (offset=0; offset<data_size; ) {
        ret=read(fd, data+offset, data_size-offset);
        if (ret<0) { warning("Unable to read from random device."); goto error; }
        offset+=ret;
    }
    status=1;
error:
    if (fd>0) close(fd);
    return status;
}

int bin_to_readable(char* out_data, size_t max_out_size, const uint8_t* in_data, size_t in_size) {
    static const char alpha[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    static const size_t alen=sizeof(alpha)-1;
    size_t i; int status=0;
    assert(out_data && in_data);
    if (max_out_size < in_size) goto error;
    for (i=0;i<in_size;++i) out_data[i]=alpha[(size_t)in_data[i]%alen];
    status=1;
error:
    return status;
}

static void fprintf_hex_cb(void* arg, const char* s) { fputs(s, (FILE*)arg); }

static void hex_print_indent(size_t indent, void(*cb)(void*,const char*), void* arg) {
    size_t i; for(i=0;i<indent;++i) (*cb)(arg,"  ");
}

int hex_print_internal(const void* data, size_t data_size, size_t indent,
                        void(*cb)(void*,const char*), void* arg) {
    static const char* digits="0123456789ABCDEF";
    const uint8_t* p=(const uint8_t*)data;
    char tmp[4]={0}; uint8_t c; size_t i; int status=0;
    if (!data||!cb) goto error;
    if (!data_size) goto done;
    hex_print_indent(indent,cb,arg);
    for (i=0;i<data_size;++i) {
        if (i>0&&(i&0xF)==0) { (*cb)(arg,"\n"); hex_print_indent(indent,cb,arg); }
        c=p[i]; tmp[0]=digits[c>>4]; tmp[1]=digits[c&0xF]; (*cb)(arg,tmp);
        if (i+1<data_size) (*cb)(arg," ");
    }
    (*cb)(arg,"\n");
done:
    status=1;
error:
    return status;
}

void fprintf_hex(FILE* fp, const void* data, size_t data_size, size_t indent) {
    hex_print_internal(data, data_size, indent, fprintf_hex_cb, fp);
}

struct snh_args { char* buf; size_t max; size_t off; };
static void snprintf_hex_cb(void* arg, const char* s) {
    struct snh_args* a=(struct snh_args*)arg;
    size_t len=strlen(s);
    if (isspace((unsigned char)*s)) return;
    if (a->off+len+1>a->max) return;
    strcpy(a->buf+a->off, s);
    a->off+=len;
    a->buf[a->off]='\0';
}
void snprintf_hex(char* s, size_t max_size, const void* data, size_t data_size) {
    struct snh_args args={s,max_size,0};
    memset(s,0,max_size);
    hex_print_internal(data,data_size,0,snprintf_hex_cb,&args);
}
