#include <stdio.h>
#include <stdlib.h>

int a;

int main() {
	a = 5; // .bss test

	int b = 10; // stack test

	int *c = (int*) malloc(sizeof(int)); // heap test
	*c = 15;

	const int d = 20; // .rodata test

	printf("a: %d\tb: %d\tc: %d\td: %d\n", a, b, *c, d); // PLT test (.plt and .got.plt)

	return 0;
}
