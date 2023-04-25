#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <vector>
#include <cstdint>
#include<iomanip>
#include <string>
#include <fstream>
using namespace std;
// Constants for SHA-256 algorithm
const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

    // Function to perform right rotate on a 32-bit value
    inline uint32_t rightRotate(uint32_t value, int n) {
        return (value >> n) | (value << (32 - n));
    }

    class SHA256 {
public:
    static std::string sha256(const std::string& message) {
      
       // Constants
const uint32_t K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


        
        // Initial hash values
 uint32_t H[] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};


        // Pre-processing: pad the message
        std::vector<uint8_t> paddedMessage = padMessage(message);
        //    cout<<paddedMessage[0]<<endl;
        //    cout<<paddedMessage[1]<<endl;
        // Process the message in 512-bit chunks
        for (size_t i = 0; i < paddedMessage.size(); i += 64) {
            std::vector<uint32_t> chunk = createChunk(paddedMessage, i);
           // Call processChunk as a static member function
          
             processChunk(chunk, H, K);

        }

        // Convert the final hash values to hex string
        std::stringstream ss;
        for (int i = 0; i < 8; i++) {
            ss << std::hex << std::setfill('0') << std::setw(8) << H[i];
        }

        // Return the final hash as a hex string
        return ss.str();
    }


private:
    static std::vector<uint8_t> padMessage(const std::string& message) {
    // Get the length of the input message in bytes
    size_t messageLength = message.length();

    // Calculate the number of bytes needed for padding
    size_t paddingBytes = 64 - ((messageLength + 8) % 64);

    // Create a buffer to hold the padded message
    std::vector<uint8_t> paddedMessage(messageLength + paddingBytes + 8);

    // Copy the input message to the padded message buffer
    std::memcpy(&paddedMessage[0], message.c_str(), messageLength);

    // Add the padding bit '1' at the end of the message
    paddedMessage[messageLength] = 0x80;

    // Add the message length in bits at the end of the padded message
    uint64_t bitLength = static_cast<uint64_t>(messageLength) * 8;
    for (int i = 0; i < 8; ++i) {
        paddedMessage[paddingBytes + messageLength + i + 1] = (bitLength >> (56 - i * 8)) & 0xFF;
    }

    return paddedMessage;
}


    static std::vector<uint32_t> createChunk(const std::vector<uint8_t>& paddedMessage, size_t offset) {
    // Create a 512-bit chunk buffer
    std::vector<uint32_t> chunk(16,0);
   
    // Copy 16 32-bit values from the padded message to the chunk buffer
    for (int i = 0; i < 16; ++i) {
        chunk[i] = static_cast<uint32_t>(paddedMessage[offset + i * 4]) << 24 |
                   static_cast<uint32_t>(paddedMessage[offset + i * 4 + 1]) << 16 |
                   static_cast<uint32_t>(paddedMessage[offset + i * 4 + 2]) << 8 |
                   static_cast<uint32_t>(paddedMessage[offset + i * 4 + 3]);
    }
     
    return chunk;
    }


    static void processChunk(std::vector<uint32_t>& chunk, uint32_t* H, const uint32_t* K) {
    // Validate input parameters
    if (chunk.size() != 16) {
        throw std::runtime_error("Invalid chunk size");
    }

    // Prepare working variables
    uint32_t a = H[0];
    uint32_t b = H[1];
    uint32_t c = H[2];
    uint32_t d = H[3];
    uint32_t e = H[4];
    uint32_t f = H[5];
    uint32_t g = H[6];
    uint32_t h = H[7];

    // Main loop for processing the chunk
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + K[i] + chunk[i];
        uint32_t S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    // Update the hash values with the result
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
}

   
};


