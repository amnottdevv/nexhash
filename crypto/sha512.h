// sha512.h
#ifndef SHA512_H
#define SHA512_H

#include <string>
#include <cstdint>

class SHA512 {
public:
    SHA512();
    void reset();
    void update(const uint8_t* data, size_t length);
    void update(const std::string& data);
    std::string final();  // returns hex digest
    static std::string hash(const std::string& data); // one-shot

private:
    void transform(const uint8_t* chunk);
    void padAndFinalize();

    uint64_t state[8];
    uint64_t bitlen;
    uint8_t buffer[128];
    size_t bufferlen;
};

#endif