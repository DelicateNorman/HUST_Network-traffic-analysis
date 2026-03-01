#pragma once
#include <string>
#include <cstdint>

/**
 * ip_utils.h
 * Utility functions for converting between dotted-decimal IP strings and
 * 32-bit unsigned integers (network byte order big-endian style).
 */

/// Convert dotted-decimal IP string to 32-bit integer.
/// Returns 0 and sets ok=false on parse failure.
uint32_t ip_to_int(const std::string& ip, bool& ok);

/// Convert 32-bit integer back to dotted-decimal string.
std::string int_to_ip(uint32_t n);
