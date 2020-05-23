#! /bin/bash

gcc -c -o local.o -fPIC local.c && ld local.o -shared -o local.so; rm local.o
