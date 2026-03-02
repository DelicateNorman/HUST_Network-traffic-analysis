#ifndef LOGGER_H
#define LOGGER_H

#include <fstream>
#include <mutex>
#include <string>

enum class LogLevel { INFO, WARN, ERROR };

/**
 * @class Logger
 * @brief Thread-safe Singleton Logger implementation for enterprise-grade
 * tracking.
 *
 * Provides a standardized way to record application events, warnings,
 * and errors to a continuous log file (logs/app.log), complete with timestamps.
 */
class Logger {
public:
  static Logger &get_instance();

  // Disable copy/move
  Logger(const Logger &) = delete;
  Logger &operator=(const Logger &) = delete;

  /**
   * @brief Initialize the logger with a file path.
   * @param filepath Target file to append logs to.
   * @return True if initialized successfully.
   */
  bool init(const std::string &filepath);

  /**
   * @brief Log a message with a specific severity level.
   */
  void log(LogLevel level, const std::string &message);

  void info(const std::string &message);
  void warn(const std::string &message);
  void error(const std::string &message);

private:
  Logger() = default;
  ~Logger();

  std::ofstream log_file_;
  std::mutex mutex_;
  bool initialized_ = false;

  std::string current_time();
  std::string level_to_string(LogLevel level);
};

#endif // LOGGER_H
