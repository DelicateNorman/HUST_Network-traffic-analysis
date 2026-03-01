#include "csv_reader.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

/**
 * csv_reader.cpp
 * FR-1: CSV parsing implementation.
 * - Skips header row
 * - Handles ICMP rows with empty SrcPort/DstPort
 * - Records and skips malformed/empty lines
 */

static std::vector<std::string> split_csv_line(const std::string &line) {
  std::vector<std::string> fields;
  std::string field;
  bool in_quote = false;
  for (char c : line) {
    if (c == '"') {
      in_quote = !in_quote;
    } else if (c == ',' && !in_quote) {
      fields.push_back(field);
      field.clear();
    } else {
      field += c;
    }
  }
  fields.push_back(field);
  return fields;
}

static std::string trim(const std::string &s) {
  size_t start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos)
    return "";
  size_t end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

ReadResult read_csv(const std::string &path) {
  ReadResult result;
  result.total_lines = 0;
  result.parsed_ok = 0;
  result.skipped = 0;

  std::ifstream f(path);
  if (!f.is_open()) {
    std::cerr << "[ERROR] Cannot open file: " << path << "\n";
    return result;
  }

  std::string line;
  bool first = true;
  int line_num = 0;

  while (std::getline(f, line)) {
    // Strip Windows-style \r
    if (!line.empty() && line.back() == '\r')
      line.pop_back();

    if (first) {
      first = false;
      continue;
    } // skip header
    line_num++;

    // Skip blank lines
    if (trim(line).empty()) {
      result.total_lines++;
      result.skipped++;
      continue;
    }
    result.total_lines++;

    auto fields = split_csv_line(line);
    if (fields.size() != 7) {
      std::cerr << "[WARN] Line " << line_num << ": expected 7 fields, got "
                << fields.size() << " - skipped\n";
      result.skipped++;
      continue;
    }

    SessionRecord rec;
    rec.source = trim(fields[0]);
    rec.destination = trim(fields[1]);

    // Parse protocol
    try {
      rec.protocol = std::stoi(trim(fields[2]));
    } catch (...) {
      std::cerr << "[WARN] Line " << line_num << ": bad Protocol - skipped\n";
      result.skipped++;
      continue;
    }

    // SrcPort / DstPort may be empty for ICMP
    std::string sp = trim(fields[3]);
    std::string dp = trim(fields[4]);
    rec.src_port = sp.empty() ? 0 : std::stoi(sp);
    rec.dst_port = dp.empty() ? 0 : std::stoi(dp);

    // DataSize
    try {
      rec.data_size = std::stoll(trim(fields[5]));
    } catch (...) {
      std::cerr << "[WARN] Line " << line_num << ": bad DataSize - skipped\n";
      result.skipped++;
      continue;
    }

    // Duration
    try {
      rec.duration = std::stod(trim(fields[6]));
    } catch (...) {
      std::cerr << "[WARN] Line " << line_num << ": bad Duration - skipped\n";
      result.skipped++;
      continue;
    }

    if (rec.source.empty() || rec.destination.empty()) {
      std::cerr << "[WARN] Line " << line_num << ": empty IP - skipped\n";
      result.skipped++;
      continue;
    }

    result.records.push_back(rec);
    result.parsed_ok++;
  }

  return result;
}
