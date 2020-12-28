#include <stdio.h>

int main(int argc, char * argv[])
{
	char buffer[1024];
	read(0, buffer, 5);
	printf("%x\n", buffer[0]);

	if (buffer[0] == 'a')
	{
		printf("1a!\n");
	}
	else
	{
		printf("b\n");
	}

	return 0;
}
