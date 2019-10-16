#ifndef LOGGER_H
#define LOGGER_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include "util.hpp"

#include <string>

using namespace std;

/**
 * Enum type representing the priority of messages.
 * Options to pass to libDetLog() for importance of message.
 */
enum class Importance {
  inter, /*< We intercepted this system call */
  info, /*< Less important information */
  extra, /*< Extra information not useful most of the time. */
};

/**
 * Enum of log color.
 */
enum class Color {
  green,
  red,
  blue,
};

/**
 * Simple logger.
 * Write debug info and other information of interest to a file without
 * polluting stderr or stdout. Based off the detmonad libdet logger.
 */
class logger {
public:
  /**
   * Constructor.
   * Requires file to write to and debug level to use.
   * @param logFile: Path to write log file to. A unique suffix will be
   * appended.
   * @param debugLevel debugging level
   * @param useColor whether to use color in logging (default true)
   */
  logger(string logFile, int debugLevel, bool useColor = true);

  /**
   * Logging wrapper for printf.
   * Decides wether to print based on debug level.
   * Uses debugLevel global.
   * Currently:
   * Level 5: Print all.
   * Level 4: Print information, errors, and intercepted call.s
   * Level 2, 3: Print errors and intercepted calls.
   * Level 1   : Print only errors.
   * Note 2, 3 work the same. This may change in the future.
   *
   * @param imp: The importance of the message.
   * @param format: message to print.
   * ... : arguments to format string.
   */
  void writeToLog(Importance imp, std::string format, ...);

  /** Just like writeToLog() but don't interpret % codes in the string */
  void writeToLogNoFormat(Importance imp, std::string s);

  /**
   * Set padding.
   */
  void setPadding();

  /**
   * Unset padding.
   */
  void unsetPadding();

  /**
   * Retrieve current debug level.
   * @return current debug level
   */
  int getDebugLevel();

  /**
   * Return new string meant to be printed in color to terminal.
   * @param color color to be displayed
   * @param text text to write
   * @return string to be printed
   */
  string makeTextColored(Color color, string text);

private:
  /**
   * Level of debugging (1-5).
   * C++ makes it a pain to initialize this if it's const.
   */
  const int debugLevel;

  const bool
      useColor; /**< Flag to tell us to use colors or not! Useful for writing
                   output to files without annoying color sequences in file. */

  FILE* fin; /**< File pointer to write to.   */

  bool padding; /**< Add a 2 space padding to the string to print. Useful for
                   nested messages. */

  uint64_t logEntryID = 0;

  bool logPrintfFormattingEnabled; /**< Whether to enable interpretation of
                                      printf format specifiers within log
                                      messages */
};
#endif
