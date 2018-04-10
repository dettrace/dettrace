#include <err.h>
#include <sys/syscall.h>
#include <linux/limits.h>
#include <unistd.h>

#include <iostream>

#include "util.hpp"

using namespace std;

/*======================================================================================*/
char* getEnvVar(char* var, bool dieIfNotSet){
  char* tempResult = getenv(var);

  if(tempResult == NULL && dieIfNotSet){
    /* Do not make this a call to libDetLog, we need to fetch the env for DEBUG before
       we make a call to it. */
    fprintf(stderr, "  [Detbox] Util library: Unable to read env variable %s\n", var);
  }
  if(tempResult == NULL){
    return NULL;
  }
  char* returnVar = (char*) malloc(sizeof(char) * strlen(tempResult) + 1);
  strcpy(returnVar, tempResult);
  return returnVar;
}
/*======================================================================================*/
int parseNum(const char* const numToParse){
  // Required to check error condition of strtol.
  char* endptr;

  int num = strtol(numToParse, &endptr, 10);
  if(endptr == numToParse){
    fprintf(stderr, "util::parseNum: Cannot convert string \"%s\" into an integer.\n", numToParse);
    exit(1);
  }
  else if (*endptr == '\0') { /* Success, reached the end of the string. */ }
  else{ // Only some part of the string was converted.
    fprintf(stderr, "util::parseNum: Cannot convert string \"%s\" into an integer.\n", numToParse);
    exit(1);
  }

  return num;
}
/*======================================================================================*/
int doWithCheck(int returnValue, string errorMessage){
  string reason = strerror(errno);
  if(returnValue == -1){
    cerr << errorMessage + ":\n  " + reason << endl;
    exit(1);
  }

  return returnValue;
}
/*======================================================================================*/
