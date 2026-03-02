#include "logger.h"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

Logger &Logger::get_instance() {
  static Logger instance;
  return instance;
}

Logger::~Logger() {
  if (log_file_.is_open()) {
    log_file_.close();
  }
}

bool Logger::init(const std::string &filepath) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (initialized_)
    return true;

  log_file_.open(filepath, std::ios::app);
  if (!log_file_.is_open()) {
    std::cerr << "[ERROR] Logger failed to open file: " << filepath << "\n";
    return false;
  }
  initialized_ = true;
  return true;
}

std::string Logger::current_time() {
  auto now = std::chrono::system_clock::now();
  auto in_time_t = std::chrono::system_clock::to_time_t(now);
  std::stringstream ss;
  ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S");
  return ss.str();
}

std::string Logger::level_to_string(LogLevel level) {
  switch (level) {
  case LogLevel::INFO:
    return "INFO";
  case LogLevel::WARN:
    return "WARN";
  case LogLevel::ERROR:
    return "ERROR";
  default:
    return "UNKNOWN";
  }
}

void Logger::log(LogLevel level, const std::string &message) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!initialized_)
    return;

  log_file_ << "[" << current_time() << "] [" << level_to_string(level) << "] "
            << message << std::endl;
}

void Logger::info(const std::string &message) { log(LogLevel::INFO, message); }
void Logger::warn(const std::string &message) { log(LogLevel::WARN, message); }
void Logger::error(const std::string &message) {
  log(LogLevel::ERROR, message);
}
