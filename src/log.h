#ifndef _LOG_H

#define _LOG_H

#define	E0	16
#define	E1	17
#define	E2	18
#define	E3	19
#define	E4	20
#define	E5	21
#define	W0	32
#define	W1	33
#define	W2	34
#define	W3	35
#define	W4	36
#define	W5	37
#define	I0	64
#define	I1	65
#define	I2	66
#define	I3	67
#define	I4	68
#define	I5	69
#define	D0	128
#define	D1	129
#define	D2	130
#define	D3	131
#define	D4	132
#define	D5	133
#define	F0	144
#define	F1	145
#define	F2	146
#define	F3	147
#define	F4	148
#define	F5	149

#ifdef NLOG
#define LOG(level, fmt, args...)	do {} while(0)
#else
#define LOG(level, fmt, args...)	log_write(level, fmt " (%s:%d)\n", ##args, __FILE__, __LINE__)
#endif

int log_open(const char *path, const char *logmask);
int log_close(void);
int log_write(char level, char *message, ...);
void log_dump_mask(void);

#endif
