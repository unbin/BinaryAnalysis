/*              local.c
  A shared library that replaces some of
  ls's dynamic functions to limit the scope
  of ls to files and directories within
  /home/user.
*/

#define _GNU_SOURCE

#include <stdio.h>
//#include <sys/stat.h>
#include <dirent.h>
//#include <sys/types.h>
#include <dlfcn.h>
#include <stdlib.h>
// opendir, stat

/*
int (*orig_stat)(const char*, struct stat*);

int stat(const char *pathname, struct stat *statbuf) {
  orig_stat = dlsym("stat", RTLD_NEXT);

  printf("%s\n", pathname);

  return orig_stat(pathname, statbuf);
}
*/

DIR* (*orig_opendir)(const char*);

DIR* opendir(const char *name) {
  if (!orig_opendir)
    orig_opendir = dlsym("opendir", RTLD_NEXT);

  if (!orig_opendir) {
    fprintf(stderr, "failed to load original opendir function\nexiting...\n");
    exit(-1);
  }
  else
    printf("successfuly loaded opendir function\n");

  printf("%s", name);

  return orig_opendir(name);
}
