
#include <err.h>
#include <sys/syscall.h>
#include <linux/limits.h>
#include <unistd.h>

#include "util.hpp"

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

bool isThisFileAScript(char* executableFullPath){
  FILE* fin = fopen(executableFullPath, "r");

  if(fin == NULL){
    err(1, "detbox::main: Error: Cannot read executable: %s.\nReason", executableFullPath);
  }

  char shebang[2 + 1];  // holds "#!" + null pointer.
  if(fgets(shebang, 3, fin) == NULL){
    err(1, "detbox::main: Error: Cannot fgets from filestream.\nReason");
  }

  fclose(fin);
  return strcmp(shebang, "#!") == 0;
}

/*======================================================================================*/

int findFullPath(const char* const fileToExpand, char* returnString){
  size_t fileLength = strlen(fileToExpand);
  if(fileLength > PATH_MAX){
    fprintf(stderr,
            "detbox::findFullPath: Error: %s is way too long to be a path!\n",
            fileToExpand);
    return 1;
  }

  // This is a relative path, nothing to expand.
  if(strstr(fileToExpand, "/") != NULL){
    strcpy(returnString, fileToExpand);
    return 0;
  }

  // Iterate through path, append path, and see if this is a file.
  // Strtok modifies string, copy to separate variable.
  const char* const paths = getenv("PATH");
  if(paths == NULL){
    fprintf(stderr,
            "detbox::findFullPath: Error: PATH does not exist in this environment!\n");
    return 1;
  }
  if(strcmp(paths, "") == 0){
    fprintf(stderr,
            "detbox::findFullPath: Error: PATH is set to empty string!\n");
    return 1;
  }

  char temp[strlen(paths) + 1];
  strcpy(temp, paths);

  for(char* thisPath = strtok(temp, ":");
      thisPath != NULL;
      thisPath = strtok(NULL, ":")){
    // We statically allocate this arrays to avoid memory manegement...
    size_t fullPathLength = strlen(thisPath) + fileLength + 1;
    char fullPath[fullPathLength];
    sprintf(fullPath, "%s/%s", thisPath, fileToExpand);

    // Check if this fullPath is a file with read and execute permissions.
    if(access(fullPath, R_OK | X_OK) == -1){
      continue;
    }else{
      // We found it. We're done.
      if(fullPathLength > PATH_MAX){
        fprintf(stderr,
                "detbox::findFullPath:"
                "Error: fullPath is longer than the maximum path length!\n");
        return 1;
      }
      strcpy(returnString, fullPath);
      return 0;
    }
  }
  // We went through all of PATH and found nothing. This is a failure.
  fprintf(stderr,
          "detbox::findFullPath: Error: Executable: '%s' not in PATH\n", fileToExpand);
  return 1;
}

/*======================================================================================*/
/**
 * The pids are out of sync if we use getpid(). Instead we wrap around
 * the raw system call.
 */
int getRealPid(){
  return syscall(SYS_getpid);
}
/*======================================================================================*/
int getRealPPid(){
  return syscall(SYS_getppid);
}

/*======================================================================================*/
int getLengthArray(char* const arr[]){
  int i;
  for (i = 0; arr[i] != NULL; i++)
    ;
  return i;
}
/*======================================================================================*/
