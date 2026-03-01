#pragma once
#include <string>
#include <vector>

/**
 * csv_reader.h
 * FR-1: Read network session records from CSV file.
 * Supports header row, handles empty/malformed lines gracefully.
 */

/// One row from network_data.csv
struct SessionRecord {
  std::string source;      ///< Source IP string
  std::string destination; ///< Destination IP string
  int protocol;            ///< Protocol number (1=ICMP, 6=TCP, 17=UDP)
  int src_port;            ///< Source port (0 if missing/ICMP)
  int dst_port;            ///< Destination port (0 if missing/ICMP)
  long long data_size;     ///< Payload bytes
  double duration;         ///< Session duration in seconds
};

struct ReadResult {
  std::vector<SessionRecord> records;
  int total_lines; ///< Total data lines (excluding header)
  int parsed_ok;   ///< Successfully parsed
  int skipped;     ///< Skipped due to errors
};

/**
 * Read CSV file and return all successfully parsed session records.
 * @param path  path to CSV file
 * @return      ReadResult with records + statistics
 */
ReadResult read_csv(const std::string &path);
