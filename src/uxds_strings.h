/* strings.h */

/* macro for memory check after malloc()/calloc() */
#define ERRNOMEM(m) \
do { \
    if (!m) { \
	fprintf(stderr, "FATAL: Not enough memory... EXITING!\n"); \
	exit(ENOMEM); \
    } \
} while (0)

/* password length for randstr() */
#define PASSLEN	8

/* shadow password input terminal handler */
int inpwd(void);

/* getpass() replacement */
char *getpwd(char *user);

/* concatenate two strings */
char *center(char *buf, char *left, char *right);

/* this is still being worked out */
void center_free(char *buf);

/* create timedate stamp format: mm-dd-yyyy hh:mm:ss */
char *curdate(void);

/* create 8 character rnd string */
char *randstr(int sz);

/* isdigit() replacement ASCII only */
int isnum(int c);

/* check if string is a pure numeral */
int strnum(char *str);

/* check for file I/O errors */
void file_chkerr(FILE * fp);

/* convert string to base64 */
char *base64(char *str, int len);
