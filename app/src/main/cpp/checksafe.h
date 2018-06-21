//
// Created by fancy shen on 2018/6/9.
//

#ifndef CRACKME2_CHECKSAFE_H
#define CRACKME2_CHECKSAFE_H

#endif //CRACKME2_CHECKSAFE_H

//
// Created by fancy shen on 2018/3/4.
//

#ifndef CHECKTRACE_CHECKSAFE_H
#define CHECKTRACE_CHECKSAFE_H

#endif //CHECKTRACE_CHECKSAFE_H

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <android/log.h>
#include <string>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sys/inotify.h>
#include <sys/wait.h>
#include <sys/queue.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <assert.h>
#include <arm-linux-androideabi/asm/ptrace.h>
#include <elf.h>
#include <assert.h>

#define LOG_TAG "checksafe"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

struct ProcInfo{
    char filename[128];
    int pid;
};

struct Step{
    int value;

};

struct Map{
    unsigned int addr;
    bool checkpoint=false;
    u_char key;
    struct Map *next;
};

Map* gMap;
Map* SaveMap;
pthread_t checkdebug;
int k[3]={1,1,1};
uint checksum[6]={239,325,147,308,306};

int readtrace(char *input,size_t len);
void logptrace(char* func,long result);
void turnit(char* input);
jint tryit(JNIEnv* env,jobject thiz,jstring input)__attribute__((section (".magic")));
void checkTid(ProcInfo *pi) __attribute__((section (".magic")));
void initmap() __attribute__((constructor));
void init_code() __attribute__((constructor));
unsigned long getLibAddr();
