#include <stdarg.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <climits>
#include <string>

#include "logger.hpp"
#include "util.hpp"

#include <stdexcept>

using namespace std;

/*======================================================================================*/
logger::logger(string logFile, int debugLevel, bool useColor)
    : debugLevel(debugLevel), useColor(useColor) {
  // Check value of debugLevel.
  if (debugLevel > 5 || debugLevel < 0) {
    fprintf(stderr, "The debug level must be between [0, 5].\n");
    exit(1);
  }

  if (logFile.empty()) {
    fin = stderr;
  } else {
    // find a unique name for our log file
    char buf[1024];
    for (int i = 0; i < 100; i++) {
      snprintf(buf, sizeof(buf), "%s.%02u", logFile.c_str(), i);
      int rv = access(buf, F_OK);
      if (0 != rv) break; // file doesn't exist, we can use this name!
    }
    FILE* logfile = fopen(buf, "w");
    VERIFY(logfile != NULL);

    fin = logfile;
  }

  padding = false;

  return;
}

void logger::writeToLogNoFormat(Importance imp, std::string s) {
  logPrintfFormattingEnabled = false;
  writeToLog(imp, s);
  logPrintfFormattingEnabled = true;
}

void logger::writeToLog(Importance imp, std::string format, ...) {
  // Don't bother, we're not printing anything.
  if (debugLevel == 0) {
    return;
  }

  va_list args;
  bool print = false;

  /* Print information based on debug level. */
  switch (debugLevel) {
    /* Most verbose, print all messages. Also does extraI. */
  case 5:
    print = true;
    break;
  case 4:
    if (imp == Importance::inter || imp == Importance::info) {
      print = true;
    }
    break;
    /* Ignore informatory messages. */
  case 3:
  case 2:
    if (imp == Importance::inter) {
      print = true;
    }
    break;
  case 1:
    break;
  case 0:
    break;
  default:
    fprintf(fin, "  Warning Unknown DEBUG level %d.\n", debugLevel);
    break;
  }

  if (print) {
    switch (imp) {
    case Importance::extra:
      fprintf(fin, "[5]EXTRA ");
      break;
    case Importance::info:
      fprintf(fin, "[4]INFO  "); // Extra space for correct alignment.
      break;
    case Importance::inter:
      fprintf(fin, "[3]INTER ");
      break;
    }
    fprintf(fin, "%lx ", logEntryID);
    logEntryID++;

    if (padding) {
      fprintf(fin, "  ");
    }

    if (logPrintfFormattingEnabled) {
      va_start(args, format);
      vfprintf(fin, format.c_str(), args);
      va_end(args);
    } else {
      fwrite(format.c_str(), 1, format.length(), fin);
    }
    fflush(fin);
  }

  return;
}

void logger::setPadding() {
  padding = true;
  return;
}

void logger::unsetPadding() {
  padding = false;
  return;
}

int logger::getDebugLevel() { return debugLevel; }

string logger::makeTextColored(Color color, string text) {
  if (!useColor) {
    return text;
  }
  string colorCode;
  const string reset{"\033[0m"};

  switch (color) {
  case Color::green:
    colorCode = "\033[1;32m";
    break;
  case Color::red:
    colorCode = "\033[1;31m";
    break;
  case Color::blue:
    colorCode = "\033[1;34m";
    break;
  default:
    runtimeError("Unkown color! Please add color code.");
  }

  return colorCode + text + reset;
}

/*======================================================================================*/
