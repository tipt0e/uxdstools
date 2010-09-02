/* afs.h */

/* AFS stuff */
typedef enum { PTSCRT, PTSGRP, PTSDEL } ptsflag;

int pts_wrap(ptsflag flag, char *ptsname, char *cellname, ...);
