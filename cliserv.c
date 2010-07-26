#include <cliserv.h>
#include <stdio.h>
#include <syslog.h>

void setmysockopt(int sock) {
#ifdef IPPROTO_TCP
	int size = 1;
	if(setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &size, sizeof(int)) < 0)
		INFO("(no sockopt/2: %m)");
#endif
}

void err(const char *s) {
	const int maxlen = 150;
	char s1[maxlen], *s2;

	strncpy(s1, s, maxlen);
	if ((s2 = strstr(s, "%m"))) {
		strcpy(s1 + (s2 - s), strerror(errno));
		s2 += 2;
		strcpy(s1 + strlen(s1), s2);
	}
#ifndef	sun
	/* Solaris doesn't have %h in syslog */
	else if ((s2 = strstr(s, "%h"))) {
		strcpy(s1 + (s2 - s), hstrerror(h_errno));
		s2 += 2;
		strcpy(s1 + strlen(s1), s2);
	}
#endif

	s1[maxlen-1] = '\0';
#ifdef ISSERVER
	syslog(LOG_ERR, "%s", s1);
	syslog(LOG_ERR, "Exiting.");
#endif
	fprintf(stderr, "Error: %s\n", s1);
	exit(1);
}

#ifdef WORDS_BIGENDIAN
u64 ntohll(u64 a) {
	return a;
}
#else
u64 ntohll(u64 a) {
	u32 lo = a & 0xffffffff;
	u32 hi = a >> 32U;
	lo = ntohl(lo);
	hi = ntohl(hi);
	return ((u64) lo) << 32U | hi;
}

void logging(char* my_name) {
#ifdef ISSERVER
	openlog(my_name, LOG_PID, LOG_DAEMON);
#endif
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

#endif
