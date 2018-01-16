#ifndef UTIL_H
#define UTIL_H

/**
 * Utility functions.
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/*======================================================================================*/
/**
 * Get env variable copy to free space and return as a heap-allocated pointer.
 * @param var: env variable to fetch from system.
 * @param dieIfNotSet: if variable is not found, should system crash?
 * @return returnVar: value of variable as string or if not found and dieifNotSet == false.
 *                    otherwise return NUll.
 */
char* getEnvVar(char* var, bool dieIfNotSet);
/*======================================================================================*/
/**
 * Given a string attemp to parse using strtol. Handles all errors by crashing and sending
 * an appropriate error. Warning: does not check for underflows!
 @param: numToParse.
 @return: parsedNum ;)
 */
int parseNum(const char* const numToParse);
#endif
/*======================================================================================*/
/**
 * Linker expects an ELF file to execute. Check if executable is a shell script.
 * TODO: This does not catch scriptse which should automatically be assumed to be bash, but
 * have no shebang patern at the beggining. We are better checking if it's an ELF file.
 */
bool isThisFileAScript(char* executableFullPath);
/*======================================================================================*/
int getRealPid();

/*======================================================================================*/
int getRealPPid();
/*======================================================================================*/
/**
 * Given a string representing a file. Check if the file is a relative path, i.e.
 * ./something, ../something something/something/...
 * If so, we leave it alone, and copy the memory of fileToExpand to returnString.
 * Otherwise, we search through $PATH and find the location
 * of this file in our system returning the complete file,
 * Enough memory must be given to returnString to fill the path. Otherwise failure!

 * @param fileToExpand: The executable/file we are trying to find full path for.
 * @param returnString: Pointer to string to copy memory to.
 * @return errorCode: 0 on success, 1 on failure.
 */
int findFullPath(const char* const fileToExpand, char* returnString);
/*======================================================================================*/
/**
 * Linker expects an ELF file to execute. Check if executable is a shell script.
 * TODO: This does not catch scriptse which should automatically be assumed to be bash, but
 * have no shebang patern at the beggining. We are better checking if it's an ELF file.
 */
bool isThisFileAScript(char* executableFullPath);
/*======================================================================================*/
int getLengthArray(char* const arr[]);
