#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/syscall.h>

#include<string>
#include <climits>

#include "logger.hpp"
#include "util.hpp"

#include<stdexcept>

using namespace std;

/*======================================================================================*/
logger::logger(FILE* myFile, int debugLevel):
debugLevel(debugLevel){
  // Check value of debugLevel.
  if(debugLevel > 5 || debugLevel < 0){
    fprintf(stderr, "The debug level must be between [0, 5].\n");
    exit(1);
  }

  fin = myFile;
  padding = false;

  return;
}

void logger::writeToLog(Importance imp, std::string format, ...){
  va_list args;
  bool print = false;

  /* Print information based on debug level. */
  switch(debugLevel){
    /* Most verbose, print all messages. Also does extraI. */
  case 5:
    print = true;
  case 4:
    if(imp == Importance::error || imp == Importance::inter || imp == Importance::info){
      print = true;
    }
    break;
    /* Ignore informatory messages. */
  case 3:
  case 2:
    if(imp == Importance::error || imp == Importance::inter){
      print = true;
    }
    break;
  case 1:
    if(imp == Importance::error){
      print = true;
    }
    break;
  case 0:
    if(imp == Importance::error){
      print = true;
    }
    break;
  default:
    fprintf(fin, "  Warning Unknown DEBUG level %d.\n", debugLevel);
    break;
  }

  if(print){
    if(padding){
      fprintf(fin, "  ");
    }
    va_start(args, format);
    vfprintf(fin, format.c_str(), args);
    va_end(args);
  }

  return;
}

void logger::setPadding(){
  padding = true;
  return;
}

void logger::unsetPadding(){
  padding = false;
  return;
}

int logger::getDebugLevel(){
  return debugLevel;
}

string logger::makeTextColored(Color color, string text){
  string colorCode;
  const string reset { "\033[0m" };

  switch(color){
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
    throw runtime_error("Unkown color! Please add color code.");
  }

  return colorCode + text + reset;
}

/*======================================================================================*/
