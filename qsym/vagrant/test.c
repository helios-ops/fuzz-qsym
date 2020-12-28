#include <stdio.h>


int a()
{
	char buffer[1024];
	int count = read(0, buffer, 1024);
	return count;
}
int main(int argc, char * argv[])
{
	// FILE * fd = fopen("/home/hhui/t0", "rb");

	char buffer[1024];
	unsigned long ptr = NULL;
	read(0, buffer, 1024);

	if ( (*((unsigned long *)buffer) == 'a') &&  (*((unsigned long *)buffer + 1) == 'b') )
	{
		*((unsigned int *)ptr ) == 1;
	}

	return 0;
}
