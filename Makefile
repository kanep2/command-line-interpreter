all: a2.c
	gcc -o cli cli.c -lm
clean: 
	$(RM) myprog