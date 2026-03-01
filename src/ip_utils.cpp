#include "ip_utils.h"
#include <sstream>
#include <stdexcept>

/**
 * ip_utils.cpp
 * Implementation of IP<->uint32 conversion.
 * Format: a.b.c.d -> (a<<24 | b<<16 | c<<8 | d)
 */

uint32_t ip_to_int(const std::string &ip, bool &ok) {
  ok = true;
  uint32_t result = 0;
  int octet = 0;
  int dots = 0;
  bool in_octet = false;

  for (size_t i = 0; i <= ip.size(); i++) {
    char c = (i < ip.size()) ? ip[i] : '.';
    if (c == '.') {
      if (!in_octet || dots > 3) {
        ok = false;
        return 0;
      }
      if (octet < 0 || octet > 255) {
        ok = false;
        return 0;
      }
      result = (result << 8) | (uint32_t)octet;
      octet = 0;
      in_octet = false;
      dots++;
    } else if (c >= '0' && c <= '9') {
      octet = octet * 10 + (c - '0');
      in_octet = true;
    } else {
      ok = false;
      return 0;
    }
  }
  if (dots != 4) {
    ok = false;
    return 0;
  }
  return result;
}

std::string int_to_ip(uint32_t n) {
  return std::to_string((n >> 24) & 0xFF) + "." +
         std::to_string((n >> 16) & 0xFF) + "." +
         std::to_string((n >> 8) & 0xFF) + "." + std::to_string(n & 0xFF);
}
