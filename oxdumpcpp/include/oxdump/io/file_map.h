// oxdump/io/file_map.h — read-only file mapping. Zero copies, raw view only.
//
// Portable across Linux/macOS (POSIX mmap) and Windows
// (CreateFileMappingW + MapViewOfFile). The public API is identical on all
// platforms:
//
//     auto fm = oxdump::io::FileMap::open(path);   // throws std::runtime_error
//     ByteView v = fm.view();
//
// mmap-обёртка. Ноль копий, только сырое view. На Windows используем
// CreateFileMappingW + MapViewOfFile; API одинаков на всех платформах.
#pragma once
#include "oxdump/common.h"
#include <cstdio>
#include <stdexcept>
#include <string>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#else
#  include <sys/mman.h>
#  include <sys/stat.h>
#  include <fcntl.h>
#  include <unistd.h>
#endif

namespace oxdump::io {

#ifdef _WIN32

// ── Windows: file mapping via CreateFileMappingW / MapViewOfFile ──────────
class FileMap {
public:
    FileMap() = default;

    // Открыть файл в read-only отображение. Кидает std::runtime_error, если
    // файла нет, он пуст или отображение не удалось. Категорию ошибки выбирает
    // вызывающий (см. main.cpp / MetadataError / BinaryError).
    static FileMap open(const std::string& path) {
        FileMap fm;
        // Path is UTF-8; widen for the W API so non-ASCII paths work too.
        std::wstring wpath = widen(path);
        fm.file_ = ::CreateFileW(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                 nullptr, OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL, nullptr);
        if (fm.file_ == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("не могу открыть файл: " + path);
        }
        LARGE_INTEGER li{};
        if (!::GetFileSizeEx(fm.file_, &li)) {
            ::CloseHandle(fm.file_);
            throw std::runtime_error("stat не смог: " + path);
        }
        fm.size_ = static_cast<std::size_t>(li.QuadPart);
        if (fm.size_ == 0) {
            ::CloseHandle(fm.file_);
            throw std::runtime_error("пустой файл: " + path);
        }
        fm.mapping_ = ::CreateFileMappingW(fm.file_, nullptr, PAGE_READONLY,
                                           0, 0, nullptr);
        if (!fm.mapping_) {
            ::CloseHandle(fm.file_);
            throw std::runtime_error("mmap не смог: " + path);
        }
        void* p = ::MapViewOfFile(fm.mapping_, FILE_MAP_READ, 0, 0, 0);
        if (!p) {
            ::CloseHandle(fm.mapping_);
            ::CloseHandle(fm.file_);
            throw std::runtime_error("mmap не смог: " + path);
        }
        fm.ptr_ = static_cast<const u8*>(p);
        return fm;
    }

    FileMap(FileMap&& o) noexcept
        : file_(o.file_), mapping_(o.mapping_), ptr_(o.ptr_), size_(o.size_) {
        o.file_ = INVALID_HANDLE_VALUE;
        o.mapping_ = nullptr;
        o.ptr_ = nullptr;
        o.size_ = 0;
    }
    FileMap& operator=(FileMap&& o) noexcept {
        if (this != &o) {
            close();
            file_ = o.file_; mapping_ = o.mapping_;
            ptr_ = o.ptr_; size_ = o.size_;
            o.file_ = INVALID_HANDLE_VALUE; o.mapping_ = nullptr;
            o.ptr_ = nullptr; o.size_ = 0;
        }
        return *this;
    }
    ~FileMap() { close(); }
    FileMap(const FileMap&) = delete;
    FileMap& operator=(const FileMap&) = delete;

    ByteView view() const noexcept { return ByteView{ptr_, size_}; }
    std::size_t size() const noexcept { return size_; }
    const u8* data() const noexcept { return ptr_; }

private:
    static std::wstring widen(const std::string& s) {
        if (s.empty()) return {};
        int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(),
                                      static_cast<int>(s.size()), nullptr, 0);
        std::wstring w(static_cast<std::size_t>(n), L'\0');
        ::MultiByteToWideChar(CP_UTF8, 0, s.data(),
                              static_cast<int>(s.size()), w.data(), n);
        return w;
    }

    void close() noexcept {
        if (ptr_) { ::UnmapViewOfFile(ptr_); ptr_ = nullptr; }
        if (mapping_) { ::CloseHandle(mapping_); mapping_ = nullptr; }
        if (file_ != INVALID_HANDLE_VALUE) {
            ::CloseHandle(file_); file_ = INVALID_HANDLE_VALUE;
        }
    }

    HANDLE file_ = INVALID_HANDLE_VALUE;
    HANDLE mapping_ = nullptr;
    const u8* ptr_ = nullptr;
    std::size_t size_ = 0;
};

#else

// ── POSIX (Linux / macOS): read-only mmap ────────────────────────────────
class FileMap {
public:
    FileMap() = default;

    // Открыть файл в read-only mmap. Кидает MetadataError/BinaryError,
    // если файла нет или mmap не смог. Категорию ошибки выбирает вызывающий.
    static FileMap open(const std::string& path) {
        FileMap fm;
        fm.fd_ = ::open(path.c_str(), O_RDONLY);
        if (fm.fd_ < 0) {
            throw std::runtime_error("не могу открыть файл: " + path);
        }
        struct stat st{};
        if (fstat(fm.fd_, &st) < 0) {
            ::close(fm.fd_);
            throw std::runtime_error("stat не смог: " + path);
        }
        fm.size_ = static_cast<std::size_t>(st.st_size);
        if (fm.size_ == 0) {
            ::close(fm.fd_);
            throw std::runtime_error("пустой файл: " + path);
        }
        void* p = mmap(nullptr, fm.size_, PROT_READ, MAP_PRIVATE, fm.fd_, 0);
        if (p == MAP_FAILED) {
            ::close(fm.fd_);
            throw std::runtime_error("mmap не смог: " + path);
        }
        fm.ptr_ = static_cast<const u8*>(p);
        return fm;
    }

    FileMap(FileMap&& o) noexcept
        : fd_(o.fd_), ptr_(o.ptr_), size_(o.size_) {
        o.fd_ = -1;
        o.ptr_ = nullptr;
        o.size_ = 0;
    }
    FileMap& operator=(FileMap&& o) noexcept {
        if (this != &o) {
            close();
            fd_ = o.fd_; ptr_ = o.ptr_; size_ = o.size_;
            o.fd_ = -1; o.ptr_ = nullptr; o.size_ = 0;
        }
        return *this;
    }
    ~FileMap() { close(); }
    FileMap(const FileMap&) = delete;
    FileMap& operator=(const FileMap&) = delete;

    ByteView view() const noexcept { return ByteView{ptr_, size_}; }
    std::size_t size() const noexcept { return size_; }
    const u8* data() const noexcept { return ptr_; }

private:
    void close() noexcept {
        if (ptr_) { munmap(const_cast<u8*>(ptr_), size_); ptr_ = nullptr; }
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
    }

    int fd_ = -1;
    const u8* ptr_ = nullptr;
    std::size_t size_ = 0;
};

#endif // _WIN32

} // namespace oxdump::io
