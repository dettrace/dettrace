#ifndef LOGGER_H
#define LOGGER_H
/**
 * Simple logger to write debug info and other information of interest to a file without
 * polluting stderr or stdout. Based off the detmonad libdet logger.
 */
#include <unistd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include "util.hpp"

#include<string>

/*======================================================================================*/
/**
 * Type representing the priority of messages.
 * Options to pass to libDetLog() for importance of message.
 */
enum class Importance {
  error,     /* This is a fatal error. */
  inter,     /* We intercepted this system call */
  info,      /* Less important information */
  extra,     /* Extra information not useful most of the time. */
};


/*======================================================================================*/
class logger {
public:
  /**
   * Constructor. Requires file to write to and debug level to use.
   */
  logger(FILE* myFile, int debugLevel);
  /**
   * Wrapper for printf. Decides wether to print based on debug level.
   * @param imp: The importance of the message.
   * @param format: message to print.
   * @param fin: FILE handle to write to.
   * ... : arguments to format string.

   * Uses debugLevel global.
   * Currently:
   * Level 5: Print all.
   * Level 4: Print information, errors, and intercepted calls.
   * Level 2, 3: Print errors and intercepted calls.
   * Level 1   : Print only errors.

   * Note 2, 3 work the same. This may change in the future.
   */
  void writeToLog(Importance imp, std::string format, ...);

  /**
   * Wrapper for @writeToLog() using errorI. This function cannot exists as C/C++
   * does not allow us to pass variadic arguments to other functions :/
   */
  /* void writeError(std::string format, ...); */

  /**
   * Set padding.
   */
  void setPadding();

  /**
   * Unset padding.
   */
  void unsetPadding();

private:
  /**
   * C++ makes it a pain to initialize this if it's const...
   */
  int debugLevel;
  /**
   * File pointer to write to.
   */
  FILE* fin;
  /**
   * Add a 2 space padding to the string to print. Useful for nested messages.
   */
  bool padding;
  /*======================================================================================*/
};
#endif
