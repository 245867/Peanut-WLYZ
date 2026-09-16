#pragma once
#include <string>
#include <vector>

std::string Base64Encode(const std::vector<unsigned char>& data);
std::vector<unsigned char> Base64Decode(const std::string& base64_data);
std::string GenerateRandomNonce(size_t length = 24);
