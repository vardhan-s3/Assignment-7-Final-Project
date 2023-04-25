#include <iostream>
#include <fstream>
#include <string>
#include "sha256.cpp"

int main() {
    // Read content from URL
    std::string url = "https://quod.lib.umich.edu/cgi/r/rsv/rsv-idx?type=DIV1&byte=4697892";
    std::string content;
    // You can use a library like cURL or libcurl to fetch the content from the URL
    // and store it in the 'content' string variable

    // Calculate SHA-256 hash
    std::string hash = SHA256::sha256(content);

    // Output hash to console
    std::cout << "SHA-256 hash: " << hash << std::endl;

    // Store hash in output.txt
    std::ofstream outfile("output.txt");
    if (outfile.is_open()) {
        outfile << "SHA-256 hash: " << hash << std::endl;
        outfile.close();
        std::cout << "Hash stored in output.txt" << std::endl;
    } else {
        std::cerr << "Failed to open output.txt" << std::endl;
        return 1;
    }

    return 0;
}
