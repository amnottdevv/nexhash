// sha256.h
#ifndef SHA256_H
#define SHA256_H

#include <string>
#include <cstdint>

class SHA256 {
public:
    SHA256();
    void reset();               // <-- TAMBAHKAN BARIS INI
    void update(const uint8_t* data, size_t length);
    void update(const std::string& data);
    std::string final();        // returns hex digest
    static std::string hash(const std::string& data); // one-shot

private:
    void transform(const uint8_t* chunk);
    void padAndFinalize();

    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buffer[64];
    size_t bufferlen;
};

#endif