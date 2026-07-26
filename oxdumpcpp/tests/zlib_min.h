// tests/zlib_min.h — минимальный self-contained прототип zlib для теста.
//
// На этой машине системного <zlib.h> нет, а NDK-шный тянет несовместимый
// bionic-sysroot. Нам для проверки round-trip нужен только raw inflate, поэтому
// объявляем ровно те символы zlib, что вызываем, и линкуемся с /lib64/libz.so.1.
// Раскладка z_stream совпадает с public ABI zlib 1.2.x.
//
// Только для тестов. Основной бинарь oxdump zlib не использует.
#pragma once
#include <cstddef>

extern "C" {

typedef unsigned char  Bytef;
typedef unsigned int   uInt;
typedef unsigned long  uLong;
typedef void*          voidpf;

typedef voidpf (*alloc_func)(voidpf opaque, uInt items, uInt size);
typedef void   (*free_func)(voidpf opaque, voidpf address);

struct internal_state;

typedef struct z_stream_s {
    const Bytef* next_in;
    uInt         avail_in;
    uLong        total_in;
    Bytef*       next_out;
    uInt         avail_out;
    uLong        total_out;
    const char*  msg;
    struct internal_state* state;
    alloc_func   zalloc;
    free_func    zfree;
    voidpf       opaque;
    int          data_type;
    uLong        adler;
    uLong        reserved;
} z_stream;
typedef z_stream* z_streamp;

#define Z_NO_FLUSH   0
#define Z_OK         0
#define Z_STREAM_END 1
#define Z_BUF_ERROR (-5)

const char* zlibVersion(void);
int inflateInit2_(z_streamp strm, int windowBits,
                  const char* version, int stream_size);
int inflate(z_streamp strm, int flush);
int inflateEnd(z_streamp strm);

#define inflateInit2(strm, windowBits) \
    inflateInit2_((strm), (windowBits), zlibVersion(), (int)sizeof(z_stream))

} // extern "C"
