#ifndef UTIL_H
#define UTIL_H

/**
 * Utility functions.
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>

using namespace std;
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
// =======================================================================================
/**
 * Call clib function that returns an integer and sets errno with automatic checking
 * and exiting on -1. Returns returnValue on success.
 *
 * Example:
 * doWithCheck(mount(cwd, pathToBuild.c_str(), nullptr, MS_BIND, nullptr),
 *             "Unable to bind mount cwd");
 */
int doWithCheck(int returnValue, string errorMessage);
// =======================================================================================
#endif
