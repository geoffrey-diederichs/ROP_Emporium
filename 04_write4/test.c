#include <stdio.h>

int main()
{
	FILE *file;
	file = fopen("flag.txt", "r");
	
	if (file != (FILE *)0)
	{
		char buff[50];
		fgets(buff, 50, file);
		puts(buff);
	}

	return 0;
}
