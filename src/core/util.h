#ifndef C51CC_UTIL_H
#define C51CC_UTIL_H

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#include <wchar.h>
#include <wctype.h>
#endif
#include "list.h"

typedef struct {
    char *body;
    int nalloc, len;
} String;

static List *cstrings = &EMPTY_LIST;

#define INIT_SIZE 8

static inline String make_string(void)
{
    return (String){
        .body = calloc(1, INIT_SIZE),
        .nalloc = INIT_SIZE,
        .len = 0,
    };
}

static inline void realloc_body(String *s)
{
    int newsize = s->nalloc * 2;
    char *body = realloc(s->body, newsize);
    s->body = body;
    s->nalloc = newsize;
}

static inline char *get_cstring(const String s)
{
    char *r = s.body;
    list_push(cstrings, r);
    return r;
}

static inline void string_append(String *s, char c)
{
    if (s->nalloc == (s->len + 1))
        realloc_body(s);
    s->body[s->len++] = c;
    s->body[s->len] = '\0';
}

static inline void string_appendf(String *s, char *fmt, ...)
{
    va_list args;
    while (1) {
        int avail = s->nalloc - s->len;
        va_start(args, fmt);
        int written = vsnprintf(s->body + s->len, avail, fmt, args);
        va_end(args);
        if (written < 0 || avail <= written) {
            realloc_body(s);
            continue;
        }
        s->len += written;
        return;
    }
}



static inline char *quote_cstring(char *p)
{
    String s = make_string();
    for (; *p; p++) {
        if (*p == '\"' || *p == '\\')
            string_appendf(&s, "\\%c", *p);
        else if (*p == '\n')
            string_appendf(&s, "\\n");
        else
            string_append(&s, *p);
    }
    return get_cstring(s);
}

#ifdef _WIN32
static inline wchar_t *c51cc_wcsdup_local(const wchar_t *src)
{
    size_t len;
    wchar_t *dst;

    if (!src) return NULL;
    len = wcslen(src);
    dst = calloc(len + 1, sizeof(wchar_t));
    if (!dst) return NULL;
    memcpy(dst, src, len * sizeof(wchar_t));
    dst[len] = L'\0';
    return dst;
}

static inline wchar_t *c51cc_win32_to_wide(const char *text)
{
    wchar_t *buf;
    int len;
    UINT codepages[3] = { CP_UTF8, CP_ACP, CP_OEMCP };

    if (!text) return NULL;

    for (int i = 0; i < 3; i++) {
        DWORD flags = (codepages[i] == CP_UTF8) ? MB_ERR_INVALID_CHARS : 0;
        len = MultiByteToWideChar(codepages[i], flags, text, -1, NULL, 0);
        if (len <= 0) continue;

        buf = calloc((size_t)len, sizeof(wchar_t));
        if (!buf) return NULL;
        if (MultiByteToWideChar(codepages[i], flags, text, -1, buf, len) > 0) {
            return buf;
        }
        free(buf);
    }

    return NULL;
}

static inline int c51cc_has_wildcard_segment(const wchar_t *segment)
{
    if (!segment) return 0;
    while (*segment) {
        if (*segment == L'?' || *segment == L'*') return 1;
        segment++;
    }
    return 0;
}

static inline wchar_t *c51cc_normalize_segment_pattern(const wchar_t *segment)
{
    size_t len;
    wchar_t *out;
    size_t j = 0;
    int wildcard = 0;

    if (!segment) return NULL;
    len = wcslen(segment);
    out = calloc(len + 2, sizeof(wchar_t));
    if (!out) return NULL;

    for (size_t i = 0; i < len; i++) {
        wchar_t ch = segment[i];
        if (ch == L'?' || ch == L'*') {
            if (!wildcard) out[j++] = L'*';
            wildcard = 1;
            continue;
        }
        wildcard = 0;
        out[j++] = ch;
    }
    out[j] = L'\0';
    return out;
}

static inline int c51cc_append_wide_path(wchar_t **path, size_t *cap, const wchar_t *segment, int force_sep)
{
    size_t cur_len;
    size_t seg_len;
    size_t need;
    wchar_t *next;

    if (!path || !cap || !*path || !segment) return 0;

    cur_len = wcslen(*path);
    seg_len = wcslen(segment);
    need = cur_len + seg_len + (force_sep ? 2 : 1);
    if (need > *cap) {
        size_t next_cap = *cap;
        while (need > next_cap) next_cap *= 2;
        next = realloc(*path, next_cap * sizeof(wchar_t));
        if (!next) return 0;
        *path = next;
        *cap = next_cap;
    }

    if (force_sep && cur_len > 0 && (*path)[cur_len - 1] != L'\\' && (*path)[cur_len - 1] != L'/') {
        (*path)[cur_len++] = L'\\';
        (*path)[cur_len] = L'\0';
    }

    memcpy(*path + cur_len, segment, (seg_len + 1) * sizeof(wchar_t));
    return 1;
}

static inline wchar_t *c51cc_resolve_win32_fuzzy_path(const wchar_t *input)
{
    const wchar_t *cursor;
    wchar_t *result;
    size_t cap = 1024;

    if (!input || !*input) return NULL;

    result = calloc(cap, sizeof(wchar_t));
    if (!result) return NULL;

    cursor = input;
    if (iswalpha((wint_t)cursor[0]) && cursor[1] == L':') {
        result[0] = cursor[0];
        result[1] = L':';
        result[2] = L'\0';
        cursor += 2;
        while (*cursor == L'\\' || *cursor == L'/') cursor++;
    }

    while (*cursor) {
        wchar_t segment[MAX_PATH];
        size_t seg_len = 0;
        wchar_t *actual = NULL;

        while (*cursor == L'\\' || *cursor == L'/') cursor++;
        if (!*cursor) break;

        while (*cursor && *cursor != L'\\' && *cursor != L'/' && seg_len + 1 < MAX_PATH) {
            segment[seg_len++] = *cursor++;
        }
        segment[seg_len] = L'\0';
        if (!seg_len) continue;

        if (c51cc_has_wildcard_segment(segment)) {
            wchar_t *pattern = c51cc_normalize_segment_pattern(segment);
            wchar_t search[MAX_PATH * 2];
            WIN32_FIND_DATAW data;
            HANDLE handle;

            if (!pattern) {
                free(result);
                return NULL;
            }

            if (result[0] && result[wcslen(result) - 1] != L'\\' && result[wcslen(result) - 1] != L'/')
                _snwprintf(search, sizeof(search) / sizeof(search[0]), L"%ls\\%ls", result, pattern);
            else
                _snwprintf(search, sizeof(search) / sizeof(search[0]), L"%ls%ls", result, pattern);
            search[(sizeof(search) / sizeof(search[0])) - 1] = L'\0';
            free(pattern);

            handle = FindFirstFileW(search, &data);
            if (handle == INVALID_HANDLE_VALUE) {
                free(result);
                return NULL;
            }

            do {
                if (wcscmp(data.cFileName, L".") != 0 && wcscmp(data.cFileName, L"..") != 0) {
                    actual = c51cc_wcsdup_local(data.cFileName);
                    break;
                }
            } while (FindNextFileW(handle, &data));
            FindClose(handle);

            if (!actual) {
                free(result);
                return NULL;
            }
        } else {
            actual = c51cc_wcsdup_local(segment);
        }

        if (!actual || !c51cc_append_wide_path(&result, &cap, actual, result[0] != L'\0')) {
            free(actual);
            free(result);
            return NULL;
        }
        free(actual);
    }

    return result;
}

static inline FILE *c51cc_fopen(const char *path, const char *mode)
{
    FILE *fp;
    wchar_t *wpath;
    wchar_t *resolved;
    wchar_t wmode[16];
    size_t mode_len;

    if (!path || !mode) return NULL;

    wpath = c51cc_win32_to_wide(path);
    if (!wpath) return fopen(path, mode);

    mode_len = strlen(mode);
    if (mode_len >= sizeof(wmode) / sizeof(wmode[0])) mode_len = sizeof(wmode) / sizeof(wmode[0]) - 1;
    for (size_t i = 0; i < mode_len; i++) wmode[i] = (wchar_t)(unsigned char)mode[i];
    wmode[mode_len] = L'\0';

    fp = _wfopen(wpath, wmode);
    resolved = NULL;
    if (!fp && wcschr(wpath, L'?')) {
        resolved = c51cc_resolve_win32_fuzzy_path(wpath);
        if (resolved) fp = _wfopen(resolved, wmode);
    }
    free(resolved);
    free(wpath);
    if (!fp) fp = fopen(path, mode);
    return fp;
}

static inline char *c51cc_resolve_path(const char *path)
{
    wchar_t *wpath;
    wchar_t *resolved = NULL;
    wchar_t fullbuf[MAX_PATH];
    char *out = NULL;
    int len;

    if (!path) return NULL;

    wpath = c51cc_win32_to_wide(path);
    if (!wpath) return strdup(path);

    if (wcschr(wpath, L'?')) {
        resolved = c51cc_resolve_win32_fuzzy_path(wpath);
    }
    if (!resolved) {
        if (_wfullpath(fullbuf, wpath, MAX_PATH)) {
            resolved = c51cc_wcsdup_local(fullbuf);
        } else {
            resolved = c51cc_wcsdup_local(wpath);
        }
    }

    len = WideCharToMultiByte(CP_ACP, 0, resolved, -1, NULL, 0, NULL, NULL);
    if (len > 0) {
        out = calloc((size_t)len, 1);
        if (out) WideCharToMultiByte(CP_ACP, 0, resolved, -1, out, len, NULL, NULL);
    }

    free(resolved);
    free(wpath);
    if (!out) out = strdup(path);
    return out;
}
#else
static inline FILE *c51cc_fopen(const char *path, const char *mode)
{
    return fopen(path, mode);
}

static inline char *c51cc_resolve_path(const char *path)
{
    return path ? strdup(path) : NULL;
}
#endif

#endif /* C51CC_UTIL_H */
