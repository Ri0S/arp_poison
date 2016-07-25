#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "networkinfo.h"

int getMIPAddress(char *dev, char *buf){
    char cmd[1000];
    FILE *fp;

    sprintf(cmd, "ifconfig %s | grep 'inet addr' | awk '{ print $2 }' | awk -F: '{print $2 }'", dev);
    fp = popen(cmd, "r");
    if(fp == NULL){
        fprintf(stderr, "getMIPAddress Error\n");
        return 0;
    }
    fgets(buf, IPSIZE, fp);
    return 1;
}

int getGIPAddress(char *dev, char *buf){
    char cmd[1000];
    FILE *fp;

    sprintf(cmd,"route | grep 'default' | awk '{ print $2 }'");
    fp = popen(cmd, "r");
    if(fp == NULL){
        fprintf(stderr, "getMIPAddress Error\n");
        return 0;
    }
    fgets(buf, IPSIZE, fp);
    return 1;
}

int getMMACAddress(char *dev, char *buf){
    char cmd[1000];
    char temp[MACSIZE];
    FILE *fp;

    sprintf(cmd, "ifconfig %s | grep 'HWaddr' | awk '{ print $5 }'", dev);
    fp = popen(cmd, "r");
    if(fp == NULL){
        fprintf(stderr, "getMIPAddress Error\n");
        exit(1);
    }
    fgets(temp, MACSIZE, fp);
<<<<<<< HEAD
    memset(buf, 0, MACASIZE);
    char *tt = strtok(temp, ":");
    buf[0] += (tt[0] >= 'a' && tt[0] <= 'f') ? (tt[0]-'a'+10)*16 : (tt[0]-'0')* 16;
    buf[0] += (tt[1] >= 'a' && tt[1] <= 'f') ? (tt[1]-'a'+10) : (tt[1]-'0');
    for(int i=1; i<MACASIZE; i++){
        tt = strtok(NULL, ":");
        buf[i] += (tt[0] >= 'a' && tt[0] <= 'f') ? (tt[0]-'a'+10)*16 : (tt[0]-'0')* 16;
        buf[i] += (tt[1] >= 'a' && tt[1] <= 'f') ? (tt[1]-'a'+10) : (tt[1]-'0');
=======

    buf[0] = (u_char)*strtok(temp, ":");
    for(int i=1; i<6; i++){
        buf[1] = (u_char)*strtok(NULL, ":");
>>>>>>> 9ed05a66cf46a8903f67cd3c60c4a7c896549312
    }
    return 1;
}
