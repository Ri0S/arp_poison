#include <stdio.h>
#define MACSIZE 18
#define MACASIZE 6
#define MTUSIZE 1500
#define IPSIZE 16
int getMIPAddress(char *dev, char *buf);
int getMMACAddress(char *dev, char *buf);
int getGIPAddress(char *dev, char *buf);
