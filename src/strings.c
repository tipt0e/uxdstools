/* 
 * strings.c
 *
 * string functions 
 * most of these return strings
 * still working valgrind.....
 * it's a process
 */

#include "uxds.h"
#include "uxds_strings.h"

/* input hider for getpwd  */
int inpwd(void)
{
    int ch;
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    newt.c_cc[VMIN] = 1;	/* Solaris complains if not 1 */
    newt.c_cc[VTIME] = 1;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    ch = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

    return ch;
}

/* get password input */
char *getpwd(char *user)
{
    int ch;
    unsigned int j = 0;
    char passget[64];
    char *catpass;
    fprintf(stdout, "%s's Password: ", user);
    fflush(stdout);
    while ((ch = inpwd()) != EOF
	   && ch != '\n' && ch != '\r' && j < sizeof(passget) - 1) {
	/* handle backspace char */
	if (ch == 0x7f && j > 0) {
	    putchar(0);
	    fflush(stdout);
	    j--;
	    passget[j] = '\0';
	}
	/* hide input */
	else if ((isalnum(ch)) || (isgraph(ch)) || (ispunct(ch))) {
	    putchar(0);
	    passget[j++] = (char) ch;
	}
    }
    /* handle NULL password entry */
    if (passget != NULL) {
	passget[j] = '\0';
    } else {
	fprintf(stdout, "\nentered password is REQUIRED.\n");
	exit(EXIT_FAILURE);
    }
    fprintf(stderr, "\n");
    catpass = strdup(passget);
    return catpass;
}

/* this I think is totally useless */
void center_free(char *buf)
{
    if (buf != NULL) {
	free(buf);
    }
}

/* concatenate two strings */
char *center(char *buf, char *left, char *right)
{
    buf =
	(char *) calloc(1, strlen(left) + strlen(right) + sizeof(char *));
    ERRNOMEM(buf);
    snprintf(buf, strlen(left) + strlen(right) + 1, "%s%s", left, right);
    buf[strlen(buf) + 1] = '\0';
    return buf;
}

/* convert realm/domain name to ldap DN - future use */
char *realmtodn(char *realm, char *buf)
{
    char *rbit;
    char *dbit;
    char *dn = calloc(1, sizeof(char *));
    memset(dn, 0, sizeof(dn));
    strncpy(dn, "dc=", 4);
    dbit = dn + 3;
    for (rbit = realm; *rbit; rbit++) {
	if (*rbit == '.') {
	    strncpy(dbit, ",dc=", 5);
	    dbit += 4;
	} else {
	    *dbit++ = *rbit;
	}
    }
    buf = strdup(dn);
    return buf;
}

/* get current date for timestamps */
char *curdate(void)
{
    char hour[3] = "";
    char min[3] = "";
    char sec[3] = "";
    char tbuf[24] = "";
    time_t now;
    struct tm *tvals;

    now = time(NULL);
    tvals = localtime(&now);

    if (tvals->tm_hour < 10) 
	snprintf(hour, 3, "0%i", tvals->tm_hour);
    else 
	snprintf(hour, 3, "%i", tvals->tm_hour);
    if (tvals->tm_min < 10)
	snprintf(min, 3, "0%i", tvals->tm_min);
    else
	snprintf(min, 3, "%i", tvals->tm_min);
    if (tvals->tm_sec < 10)
	snprintf(sec, 3, "0%i", tvals->tm_sec);
    else 
	snprintf(sec, 3, "%i", tvals->tm_sec);
    snprintf(tbuf, 22, "%i-%i-%i %s:%s:%s",
	     tvals->tm_mon + 1, tvals->tm_mday, tvals->tm_year + 1900,
	     hour, min, sec);

    char *tdate = strdup(tbuf);
    return tdate;
}

/* return random char string for 
 * password - not much entropy
 * ldap functions set it to 8 characters
 */
char *randstr(int sz)
{
    int scope = 1024;           /* this should be enough */
    int len = 0;
    char *grabchr = calloc(1, sz + 1 * sizeof(char *));
    ERRNOMEM(grabchr);
    char *random = NULL;
    int i, j, k, l;
    int ch;
    int multi = (sz / 8);
    if (!multi)
        multi = 1;
    (void) srand((int) time((time_t *) NULL));  /* seed for rand */
    j = 0;
    k = 0;
    l = 0;
    for (i = 0; i < scope; i++) {
        if (len == sz)
            break;
        ch = 33 + (int) (75.0 * rand() / (RAND_MAX));
        while (ch > 32 && ch < 123) {
            /* chars we don't want */
            if ((ch > 90 && ch < 97) || (ch == 34) || (ch == 39))
                break;
            /* we only want one at most of these */
            if ((ch > 32 && ch < 48) || (ch > 57 && ch < 65)) {
                if (j == (1 * multi))
                    break;
                j++;
            }
            /* 3 at most of these */
            if (ch > 65 && ch < 91) {
                if (k == (3 * multi))
                    break;
                k++;
            }
            /* four at most of these */
            if (ch > 96 && ch < 123) {
                if (l == (4 * multi))
                    break;
                l++;
            }
            grabchr[len] = ch;
            len++;
            break;
        }
    }
    grabchr[len] = '\0';
    random = (char *) strdup(grabchr);
    return random;
}

/* my isdigit() for ASCII only */
int isnum(int c)
{
    if (c > 57 || c < 48)
	return 1;
    return 0;
}

/* check to see if a string is a pure numeral */
int strnum(char *str)
{
    unsigned int i;
    for (i = 0; i < strlen(str); i++) {
	if (isnum(str[i]) != 0) 
	    return 1;
    }
    return 0;
}

#ifdef HAVE_LDAP_SASL_GSSAPI
/* base64 for lacctparse ldif export krb5Key */
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

char *base64(char *str, int len)
{
    BIO *target, *b64;
    BUF_MEM *ossl;

    b64 = BIO_new(BIO_f_base64());
    target = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, target);
    BIO_write(b64, str, len);
    BIO_get_mem_ptr(b64, &ossl);

    char *buf = (char *) malloc(ossl->length);
    memcpy(buf, ossl->data, ossl->length);
    buf[ossl->length] = 0;

    BIO_free_all(b64);

    return buf;
}
#endif				/* HAVE_LDAP_SASL_GSSAPI */

void file_chkerr(FILE * fp)
{
    if (fp == NULL) {
	switch (errno) {
	case EINVAL:
	    fprintf(stderr,
		    "EINVAL - invalid value passed to the function\n");
	    break;
	case EACCES:
	    fprintf(stderr, "EACCES - permission denied to open log %s\n",
		    UXDS_LOG);
	    break;
	case EDEADLK:
	    fprintf(stderr,
		    "EDEADLK - resource deadlock would occur opening %s\n",
		    UXDS_LOG);
	    break;
	case ENAMETOOLONG:
	    fprintf(stderr, "ENAMETOOLONG - file name too long\n");
	    break;
	case ENOLCK:
	    fprintf(stderr, "ENOLCK - no record locks available for %s\n",
		    UXDS_LOG);
	    break;
	case ENOSYS:
	    fprintf(stderr, "ENOSYS - function not implemented\n");
	    break;
	case ELOOP:
	    fprintf(stderr,
		    "ELOOP - too many symbolic links encountered opening %s\n",
		    UXDS_LOG);
	    break;
	default:
	    fprintf(stderr, "ERRNO is %i\n", errno);
	    break;
	}
	fprintf(stderr, "ditching on * %i *......\n", errno);
	exit(errno);
    }
}
