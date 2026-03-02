#pragma once
#include "csv_reader.h"
#include <string>
#include <vector>

/**
 * rules.h
 * FR-6: IP Range Block Rule security engine.
 * Identifies sessions that violate an IP range rule.
 *
 * Rule: given ip1, ip_low, ip_high, mode (deny|allow):
 *   deny:  any session between ip1 and [ip_low, ip_high] is a violation
 *   allow: ip1 may ONLY communicate with [ip_low, ip_high];
 *          any session with an IP outside range is a violation
 */

struct RuleViolation {
  SessionRecord session; ///< the violating session
  std::string reason;    ///< human-readable reason
};

/**
 * Apply IP range rule to all sessions.
 * @param sessions  all raw session records
 * @param ip1       the controlled IP
 * @param ip_low    range lower bound (inclusive)
 * @param ip_high   range upper bound (inclusive); auto-swapped if low>high
 * @param mode      "deny" or "allow"
 * @return          list of violations
 */
std::vector<RuleViolation>
apply_iprange_rule(const std::vector<SessionRecord> &sessions,
                   const std::string &ip1, const std::string &ip_low,
                   const std::string &ip_high, const std::string &mode);

/**
 * @brief Prints the list of rule violations in a tabular format.
 * @param violations Vector of detected rule violations.
 */
void print_violations(const std::vector<RuleViolation> &violations,
                      bool json_output = false);
