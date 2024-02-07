# [write4](https://ropemporium.com/challenge/write4.html)

Let's test the program :

```console
$ ./write4 
write4 by ROP Emporium
x86_64

Go ahead and give me the input already!

> test
Thank you!
```

# Static Analysis

Using Ghidra we can find those functions inside write4 :

```C
undefined8 main(void)
{
  pwnme();
  return 0;
}

void usefulFunction(void)
{
  print_file("nonexistent");
  return;
}
```

And those functions inside libwrite4.so :

```C
void pwnme(void)
{
  undefined local_28 [32];
  
  setvbuf(_stdout,(char *)0,2,0);
  puts("write4 by ROP Emporium");
  puts("x86_64\n");
  memset(local_28,0,32);
  puts("Go ahead and give me the input already!\n");
  printf("> ");
  read(0,local_28,512);
  puts("Thank you!");
  return;
}

void print_file(char *param_1)
{
  char local_38 [40];
  FILE *local_10;
  
  local_10 = (FILE *)0x0;
  local_10 = fopen(param_1,"r");
  if (local_10 == (FILE *)0x0) {
    printf("Failed to open file: %s\n",param_1);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  fgets(local_38,33,local_10);
  puts(local_38);
  fclose(local_10);
  return;
}
```

The read() function inside pwnme() expects 512 bytes even tho the local_28 variable is 32 bytes long. This is vulnerable to a buffer overflow.  
  
We need to exploit this vulnerability to redirect the program towards the print_file() function with "flag.txt" as an argument.

# Dynamic analysis
