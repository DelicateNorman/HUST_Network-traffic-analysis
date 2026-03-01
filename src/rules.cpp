#include "rules.h"
#include "ip_utils.h"
#include <algorithm>
#include <iomanip>
#include <iostream>

/**
 * rules.cpp
 * FR-6: IP Range Block Rule implementation.
 * IP comparison uses uint32 conversion: a.b.c.d -> (a<<24|b<<16|c<<8|d)
 */

static bool ip_in_range(const std::string &ip, uint32_t lo, uint32_t hi) {
  bool ok;
  uint32_t v = ip_to_int(ip, ok);
  if (!ok)
    return false;
  return (v >= lo && v <= hi);
}

std::vector<RuleViolation>
apply_iprange_rule(const std::vector<SessionRecord> &sessions,
                   const std::string &ip1, const std::string &ip_low,
                   const std::string &ip_high, const std::string &mode) {
  bool ok1, ok2, ok3;
  /* uint32_t ip1_int = */ ip_to_int(ip1, ok1);
  uint32_t lo = ip_to_int(ip_low, ok2);
  uint32_t hi = ip_to_int(ip_high, ok3);

  if (!ok1 || !ok2 || !ok3) {
    std::cerr << "[ERROR] Invalid IP address in rule definition\n";
    return {};
  }
  if (lo > hi)
    std::swap(lo, hi); // auto-swap

  std::vector<RuleViolation> violations;

  for (const auto &s : sessions) {
    bool involves_ip1 = (s.source == ip1 || s.destination == ip1);
    if (!involves_ip1)
      continue;

    // The other IP in the session
    std::string other = (s.source == ip1) ? s.destination : s.source;
    bool other_in_range = ip_in_range(other, lo, hi);

    if (mode == "deny") {
      // Violation: ip1 communicates with any IP in [lo, hi]
      if (other_in_range) {
        RuleViolation v;
        v.session = s;
        v.reason = "DENY rule: " + ip1 + " communicated with " + other +
                   " (in blocked range " + ip_low + "-" + ip_high + ")";
        violations.push_back(v);
      }
    } else if (mode == "allow") {
      // Violation: ip1 communicates with IP OUTSIDE [lo, hi]
      if (!other_in_range) {
        RuleViolation v;
        v.session = s;
        v.reason = "ALLOW rule: " + ip1 + " communicated with " + other +
                   " (outside allowed range " + ip_low + "-" + ip_high + ")";
        violations.push_back(v);
      }
    }
  }
  return violations;
}

void print_violations(const std::vector<RuleViolation> &violations) {
  if (violations.empty()) {
    std::cout << "No violations found.\n";
    return;
  }
  std::cout << "Found " << violations.size() << " violation(s):\n\n";
  std::cout << std::left << std::setw(18) << "Source" << std::setw(18)
            << "Destination" << std::setw(6) << "Proto" << std::setw(8)
            << "SrcPort" << std::setw(8) << "DstPort" << std::setw(12)
            << "DataSize" << std::setw(12) << "Duration"
            << "\n";
  std::cout << std::string(82, '-') << "\n";
  for (const auto &v : violations) {
    const auto &s = v.session;
    std::cout << std::left << std::setw(18) << s.source << std::setw(18)
              << s.destination << std::setw(6) << s.protocol << std::setw(8)
              << s.src_port << std::setw(8) << s.dst_port << std::setw(12)
              << s.data_size << std::fixed << std::setprecision(3)
              << std::setw(12) << s.duration << "\n";
  }
  std::cout << "\nReason sample: " << violations[0].reason << "\n";
}
