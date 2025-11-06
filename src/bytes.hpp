#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <fstream>
#include <iterator>

// read whole file into bytes
inline std::vector<uint8_t> read_all(const std::string &path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(f), {});
}

// little-endian helpers
inline uint16_t le16(const uint8_t *p) {
    return uint16_t(p[0]) | (uint16_t(p[1]) << 8);
}
inline uint32_t le32(const uint8_t *p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
inline uint64_t le64(const uint8_t *p) {
    return uint64_t(le32(p)) | (uint64_t(le32(p+4)) << 32);
}

// big-endian helpers
inline uint16_t be16(const uint8_t *p) {
    return (uint16_t(p[0])<<8) | uint16_t(p[1]);
}
inline uint32_t be32(const uint8_t *p) {
    return (uint32_t(p[0])<<24) | (uint32_t(p[1])<<16) | (uint32_t(p[2])<<8) | uint32_t(p[3]);
}