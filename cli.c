/*
    CSCI 352 Assignment 2
    Command Line Interpretter 
    
    contains built in functions:
    	exit, closes program
    	cd, changes directory
    	pwd, prints current working directory 
    	listf, implementation of ls with flags l,m,a,c
    	calc, basic calculator

    Kane Pollard, May 2016
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>  
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <math.h>
#include <libgen.h>

#define FUNC_COUNT 5 //number of functions cli has
#define ARG_DELIMS " \n\t" //delimiters for user input
#define CALC_DELIMS "/*+-" //delimiters for calc functions
#define BUFSIZE 1024
#define strtoint(str) (int) strtol(str, (char **)NULL, 10) //converts string to int

void exit_cli(char **args);
void cd(char **args);
void pwd(char **args);
void listf(char **args);
void calc(char **args);
char **parse_input(char *input, char *delims);

char *func_names[] = {"exit", "cd", "pwd", "listf", "calc"};
void (*funcs[])(char **) = {&exit_cli, &cd, &pwd, &listf, &calc};

/* function getsize()
 * returns size of array
 * parameter: char **args, args from user
 * return: int size of array
 */
int getsize(char **array) {
	int i = 0; 
	while (array[i] != NULL) {
		i++;
	}
	return i;
}

/* function exit_cli()
 * exits the cli
 * parameter: char **args, args from user
 * return: void
 */
void exit_cli(char **args) {
	
	exit(0);
}

/* function cd()
 * changes current working directory
 * parameter: char **args, args from user
 * return: void
 */
void cd(char **args) {
	
	if (!chdir(args[1])) 
		printf("cwd changed to %s\n", getcwd(NULL, 0));
	else 
		printf("no such directory: %s\n", args[1]);
}

/* function pwd
 * prints current working directory
 * parameter: char **args, args from user 
 * return: 
 */
//print current wokring directory
void pwd(char **args) {
	
	printf("%s ", getcwd(NULL, 0));

}

/* function scandir_filter()
 * filter to be used by scandir to
 * remove file starting with '.' or '..'
 * parameter: dirent *, the file in question
 * return: 1 if file starts with either
 */
int scandir_filter(const struct dirent *ent) {
	if (!strcmp (ent->d_name, ".") || !strcmp (ent->d_name, "..")) 
		return 0;
	return 1; 	
}

/* function getlen()
 * finds number of digits in a int
 * parameter: int fsize, the int 
 * return: int, number of digits
 */
int getlen(int fsize) {
	if (fsize > 0) 
		return (int)floor(log10((double)fsize)) + 1;
	else 
		return 1;
}

/* function maxfslen()
 * gets the max length between file sizes
 * in dirent **ents to be used for formating listf -l
 * parameter: dirent **ents, int n the nubmer of ents
 * return: the digits required for the largest size
 */
int maxfslen(struct dirent **ents, int n) {
	
	struct dirent *ent;
	char fpath[PATH_MAX];
	struct stat fstat;
	size_t fsize = 0; 

	//loops through each ent in ents
	for (int j = 0; j < n; j++) {
		ent = ents[j];
		realpath(ent->d_name, fpath);
		if (!stat(fpath, &fstat)) 
			//update fsize if st_size is larger
			if (fsize < fstat.st_size) 
				fsize = fstat.st_size;
	}
	return getlen((int)fsize);
}

/* function print_perms()
 * used by listf prints permissions
 * parameter: mode
 * return: void
 */
void print_perms(mode_t mode) {
	
	char ftype = 'o';

	//print file type
	if (S_ISREG(mode)) ftype = '-';
	if (S_ISDIR(mode)) ftype = 'd';
	if (S_ISLNK(mode)) ftype = 'l';
	printf("%c", ftype);
	
	//print permissions
	printf((mode & S_IRUSR) ? "r" : "-");
	printf((mode & S_IWUSR) ? "w" : "-");
	printf((mode & S_IXUSR) ? "x" : "-");
	printf((mode & S_IRGRP) ? "r" : "-");
	printf((mode & S_IWGRP) ? "w" : "-");
	printf((mode & S_IXGRP) ? "x" : "-");
	printf((mode & S_IROTH) ? "r" : "-");
	printf((mode & S_IWOTH) ? "w" : "-");
	printf((mode & S_IXOTH) ? "x" : "-");	
}

/* function print_ids()
 * used by listf, prints uid and group id
 * parameter: stat fstat
 * return: void
 */
void print_ids(struct stat fstat) {

	struct passwd *pwd;
	struct group *grp;
	
	if (pwd = getpwuid(fstat.st_uid)) 
		printf(" %s", pwd->pw_name);
	else
		printf(" %d", fstat.st_uid);
	
	if (grp = getgrgid(fstat.st_gid)) 
		printf(" %s", grp->gr_name);
	else 
		printf(" %d", fstat.st_gid);	
}

/* function print_dates()
 * used by listf, prints dates related to file
 * parameter: stat fstat, int flags[] contains flags for l,m,a,c 
 * return: void
 */
void print_dates(struct stat fstat, int flags[]) {

	char datestr[256]; 
	struct tm tm;
	
	//m flag
	if (flags[1] || (!flags[1] && !flags[2] && !flags[3])) {
		localtime_r(&fstat.st_mtime, &tm);  
		strftime(datestr, sizeof(datestr), "M%D-%H:%M", &tm);  
		printf(" %s", datestr);		
	} 
	//a flag
	if (flags[2]) {
		localtime_r(&fstat.st_atime, &tm);  
		strftime(datestr, sizeof(datestr), "A%D-%H:%M", &tm);  
		printf(" %s", datestr);	
	}
	//c flag
	if (flags[3]) {
		localtime_r(&fstat.st_ctime, &tm);  
		strftime(datestr, sizeof(datestr), "C%D-%H:%M", &tm);  
		printf(" %s", datestr);							
	}
}

/* function print_finfo()
 * used by listf, calls of the print methods
 * parameter: path of file, its name, related flags, digit length of largest size
 * return: void
 */
void print_finfo(char *fpath, char *name, int flags[], int maxlen) {
	
	struct stat fstat;
	
	if (flags[0] && !stat(fpath, &fstat)) {
		print_perms(fstat.st_mode);
		printf(" %lu", fstat.st_nlink); 
		print_ids(fstat);
		printf(" %*zu", maxlen, fstat.st_size);					
		print_dates(fstat, flags);
		printf(" %s\n", name);	
	}
	else {
		printf("%s ", name);	
	}
}

/* function do_listf()
 * does the actual work of listf 
 * parameter: file or dir path, lmac flags
 * return: void
 */
void do_listf(char *path, int flags[]) {

	char fpath[PATH_MAX + 1];
	struct dirent **ents;
	struct dirent *ent;
	struct stat fstat;
	int n, maxlen;
	
	//print info for directory path
	if (!chdir(path)) {
		n = scandir(".", &ents, scandir_filter, alphasort);
		printf ("%d entries found\n", n);
		
		if (n < 0) {
			perror("scandir");
		}
		else {
			maxlen = maxfslen(ents, n);
			for (int i = 0; i < n; i++) {
				ent = ents[i];
				if(realpath(ent->d_name, fpath)) {	
					print_finfo(fpath, ent->d_name, flags, maxlen);
				}
				free(ent);
			}		
			free(ents);
			printf("\n");
		}		
	}
	//print info for file path
	else if (realpath(path, fpath)) {	
		if (!stat(fpath, &fstat)) {
			maxlen = getlen((int)fstat.st_size);
			print_finfo(fpath, basename(path), flags, maxlen);
		} else {
			printf("stat failed");
		}
	}
	//invalid path
	else {
		printf("no file or directory found: %s\n", path);
	}
}

/* function listf_fork
 * creates a child process that does listf
 * parameter: path to file and lmac flags
 * return: void
 */
void listf_fork(char *path, int flags[]) {

	pid_t pid;	
	int status;

	if ((pid = fork()) < 0) {
		perror("error: ");
	}
	else if (pid == 0) {
		do_listf(path, flags);
		exit(1);
	} 
	else {
		waitpid(pid, &status, 0);	
	}
}

/* function listf()
 * prints the contents of provided file or directory
 * parses flags and file paths then calls helper functions
 * parameter: char **args, args from user 
 * return: void
 */
void listf(char **args) {
	
	int flags[4] = {0};
	int i = 0, dirpos = 0; 
	char *c; 
	char *dirs[256];
	//printf ("%s\n" ,args[1]);

	while (args[++i]) {
		//if arg begins with '-' parse flags
		if (!(strncmp(args[i], "-", 1))) {
			c = args[i];
			while (*c) {
				switch (*c++) {
					case 'l' : flags[0] = 1; break;
					case 'm' : flags[1] = 1; break;
					case 'a' : flags[2] = 1; break;
					case 'c' : flags[3] = 1; break;
					default : break;
				}
			}
		}  
		else 
			dirs[dirpos++] = args[i];
	}
	//if there are dirs provided
	if (dirpos) {
		for (i = 0; i < dirpos; i++) {
			listf_fork(dirs[i], flags); 
		}
	}
	//if no directories given default to "."
	else {
		listf_fork(".", flags);
	}	
}

/* function calc()
 * does simple calculations
 * parameter: char **args, args from user 
 * return: void
 */
void calc(char **args) {
	
	int a,b;
	size_t len = 0; 
	char *input;
	char **nums;  
	char *op = malloc(sizeof(char));
	char *pbrkresult;

	//get input from user
	while(getline(&input, &len, stdin) != -1) {
		
		//separate into two ints and an operator
		if (pbrkresult = strpbrk(input, CALC_DELIMS)) {
			memcpy(op, pbrkresult, sizeof(char));
			nums = parse_input(input, CALC_DELIMS);
			
			//if correct number of ints and a valid operator is provided
			if (getsize(nums) == 2 && op != NULL) {
				a = strtoint(nums[0]);
				b = strtoint(nums[1]);
				
				//if boths strings sucessfully convtered to int switch case
				//decides which type of operation to do
				if (a != -1 && b != -1) {
					switch(*op) {
						case '*' : printf("%d * %d = %d\n", a, b, a*b); break;
						case '/' : printf("%d / %d = %d\n", a, b, a/b); break;
						case '+' : printf("%d + %d = %d\n", a, b, a+b); break;
						case '-' : printf("%d - %d = %d\n", a, b, a-b); break;
						default : printf("invalid operator.\n" );
					}
				}
			}
		}
		else {
			printf("not a valid input.\n");
		} 
	}
}

/* function get_input()
 * gets input from user
 * parameter: void
 * return: input as string
 */
char *get_input(void) {

	char *input = NULL;
	size_t len = 0; 
	
	if (getline(&input, &len, stdin) == -1) {
		printf("\n");
		exit(0);
	}
	return input;
}

/* function parse_input()
 * parses input, converting it to string and finding > for i/o redirect
 * parameter: input from user, delimiters to be used for separating input
 * return: char ** array of strings
 */
char **parse_input(char *input, char *delims) {

	int pos = 0;
	char *token = strtok(input, delims);
	char **args = malloc(BUFSIZE * sizeof(char *));

	while (token) {
		args[pos++] = token;
		token = strtok(NULL, delims);
	}	
	args[pos] = NULL;
	return args; 
}

/* function exec_input()
 * either calls a built in function or runs args as external command
 * parameter: input from user
 * return: void
 */
void exec_input(char *input) {
	
	char *incpy = strdup(input);
	char **args = parse_input(incpy, ARG_DELIMS);
	
	// goes through list of build in function names
	// if arg matches a name in that list, call the 
	// function related to that name
	if (args[0]) {
		for (int i = 0; i < FUNC_COUNT; i++) {
			if (!strcmp(args[0], func_names[i])) {
				funcs[i](args);
				return;
			}
		}
		system(input);
	} 
	free(args);
}

int main (int argc, char *argv[]) {

	char *input;

	while(1) {
		printf("$> ");	
		input = get_input();
		exec_input(input);
		free(input);
	}
	return 0;
}

