#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/syscall.h>

#include<string>

#include "logger.hpp"
#include "util.hpp"

/*======================================================================================*/
logger::logger(FILE* myFile, int debugLevel){
  // Check value of debugLevel.
  if(debugLevel > 5 || debugLevel < 0){
    fprintf(stderr, "The debug level must be between [0, 5].\n");
    exit(1);
  }

  this->debugLevel = debugLevel;
  fin = myFile;
  padding = false;

  return;
}

void logger::writeToLog(Importance imp, std::string format, ...){
  va_list args;
  bool print = false;
  pid_t pid = syscall(SYS_getpid);

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


/*======================================================================================*/
