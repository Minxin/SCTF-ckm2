//
// Created by fancy shen on 2018/5/26.
//

#include "checksafe.h"
#include <string.h>
#include <sys/user.h>







void init_code(){
    char name[15];
    unsigned int text_off;
    unsigned int nblock;
    unsigned int nsize;
    unsigned long base;
    unsigned long text_addr;
    unsigned int i;
    Elf32_Ehdr *ehdr;
    Elf32_Shdr *shdr;

    //获取so的起始地址
    base = getLibAddr();

    //获取指定section的偏移值和size
    ehdr = (Elf32_Ehdr *)base;
    text_addr = (ehdr->e_ident[8] |(ehdr->e_ident[9]<<8) | (ehdr->e_ident[10]<<16) | (ehdr->e_ident[11]<<24))+ base;

    nblock = ehdr->e_entry >> 16;
    nsize = ehdr->e_entry & 0xffff;


    LOGI("nblock = %d\n", nblock);


    if(mprotect((void *) (text_addr / PAGE_SIZE * PAGE_SIZE), 4096 * nsize, PROT_READ | PROT_EXEC | PROT_WRITE) != 0){
        LOGE("mem privilege change failed");
        //__android_log_print(ANDROID_LOG_INFO, "JNITag", "mem privilege change failed");
    }

    for(i=0;i< nblock; i++){
        char *addr = (char*)(text_addr + i);
        *addr = (*addr)^(i&0xff);
    }

    if(mprotect((void *) (text_addr / PAGE_SIZE * PAGE_SIZE), 4096 * nsize, PROT_READ | PROT_EXEC) != 0){
        LOGE("mem privilege change failed");
    }
}

unsigned long getLibAddr(){
    unsigned long ret = 0;
    char name[] = "libckm.so";
    char buf[4096], *temp;
    int pid;
    FILE *fp;
    pid = getpid();
    sprintf(buf, "/proc/%d/maps", pid);
    fp = fopen(buf, "r");
    if(fp == NULL)
    {
        puts("open failed");
        goto _error;
    }
    while(fgets(buf, sizeof(buf), fp)){
        if(strstr(buf, name)){
            temp = strtok(buf, "-");
            ret = strtoul(temp, NULL, 16);
            break;
        }
    }
    _error:
    fclose(fp);
    return ret;
}

void initmap(){
    SaveMap=gMap;
    gMap=new Map();
    gMap->addr=0;
    gMap->next=new Map();
    gMap->key=87;
    Map* pMap;

    pMap=gMap->next;
    pMap->addr=0;
    pMap->key=101;
    pMap->next=new Map();

    pMap=pMap->next;
    pMap->addr=0;
    pMap->key=49;
    pMap->next=new Map();

    pMap=pMap->next;
    pMap->addr=0;
    pMap->key=99;
    pMap->next=new Map();

    pMap=pMap->next;
    pMap->addr=0;
    pMap->key=111;
    pMap->next=new Map();

    pMap=pMap->next;
    pMap->addr=0;
    pMap->key=51;
    pMap->next=new Map();

    pMap=pMap->next;
    pMap->addr=0;
    pMap->key=116;
    pMap->next=new Map();

    pMap=pMap->next;
    pMap->addr=0;
    pMap->key=48;
    pMap->next=new Map();

    pMap=pMap->next;
    pMap->addr=0;
    pMap->key=108;
    pMap->next=new Map();

    pMap=pMap->next;
    pMap->addr=0;
    pMap->key=109;
    pMap->next=new Map();

    pMap=pMap->next;
    pMap->addr=0;
    pMap->key=101;
    pMap->next=new Map();

    pMap=pMap->next;
    pMap->addr=0;
    pMap->key=108;
    pMap->next=new Map();

    pMap=pMap->next;
    pMap->addr=0;
    pMap->key=50;
    pMap->next=new Map();

    pMap=pMap->next;
    pMap->addr=0;
    pMap->key=101;
    pMap->next=new Map();

    pMap=pMap->next;
    pMap->addr=0;
    pMap->key=86;
    pMap->next=new Map();

    pMap=pMap->next;
    pMap->addr=0;
    pMap->key=0;
    pMap->checkpoint=true;
    pMap->next=NULL;
}

jint tryit(JNIEnv* env,jobject thiz,jstring input){
    const char *str = env->GetStringUTFChars(input, 0);
    size_t len=strlen(str);
    char copystr[128];
    strcpy(copystr,str);
    int result=readtrace(copystr,len);
    return result;

}


static JNINativeMethod gMethods[] = {
        {"tryit","(Ljava/lang/String;)I",(jint*)tryit},

};

static int registerNativeMethods(JNIEnv* env
        , const char* className
        , JNINativeMethod* gMethods, int numMethods) {
    jclass clazz;
    clazz = env->FindClass(className);
    if (clazz == NULL) {
        return JNI_FALSE;
    }
    if (env->RegisterNatives(clazz, gMethods, numMethods) < 0) {
        return JNI_FALSE;
    }

    return JNI_TRUE;
}
static int registerNatives(JNIEnv* env) {
    const char* kClassName = "com/fancy/crackme2/MainActivity";
    return registerNativeMethods(env, kClassName, gMethods,
                                 sizeof(gMethods) / sizeof(gMethods[0]));
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env = NULL;
    jint result = -1;

    if (vm->GetEnv((void**) &env, JNI_VERSION_1_4) != JNI_OK) {
        return -1;
    }
    assert(env != NULL);

    if (!registerNatives(env)) {
        return -1;
    }

    result = JNI_VERSION_1_4;

    return result;
}

void checkTid(ProcInfo *pi){
    FILE *fd;
    char line[128];
    while (1) {
        fd = fopen(pi->filename, "r");
        while (fgets(line, 128, fd)) {
            if (strncmp(line, "TracerPid", 9) == 0) {
                int status = atoi(&line[10]);
                LOGI("the process status is %d, %s", status, line);
                fclose(fd);
                syscall(__NR_close, fd);
                if (status != 0) {
                    LOGI("find the process was debugging");
                    kill(pi->pid, SIGKILL);
                    return;
                }
                break;
            }
        }
        sleep(3);
    }
}


int readtrace(char *input,size_t len)
{
    ProcInfo *pinfo=new ProcInfo();
    char filename[128];
    int pid=getpid();
    LOGI("PID : %d", pid);
    sprintf(filename, "/proc/%d/status", pid);
    strcpy(pinfo->filename,filename);
    pinfo->pid=pid;
    pid_t child=fork();
    if (child==0) {
        wait(NULL);
        long pt = ptrace(PTRACE_TRACEME, 0, 0, 0);
        //logptrace("child traceme",pt);
        pthread_create(&checkdebug,NULL,(void*(*)(void*))&checkTid,(ProcInfo*) pinfo);
        pthread_detach(checkdebug);
        turnit(input);

    } else if(child>0){
        int statloc;
        pt_regs regs;
        unsigned int ins1;
        //unsigned int ins2;
        //unsigned char checkbyte;
        int checkstep=0;
        wait(&statloc);
        while(1){
            //LOGI("check");
            if(WIFSTOPPED(statloc)){
                ptrace(PTRACE_GETREGS, child, 0, &regs);
                ins1=ptrace(PTRACE_PEEKTEXT,child,regs.ARM_pc,0);
                //ins2=ptrace(PTRACE_PEEKDATA,child,regs.ARM_pc-4,0);
                //checkbyte=(u_char)(ins2 & 0xff);
                if(ins1!=0xe1200070){
                    ptrace(PTRACE_KILL,child,0,0);
                    exit(0);
                }
                if(((regs.ARM_r0)&0xff)!=gMap->key){
                    ptrace(PTRACE_KILL,child,0,0);
                    gMap=SaveMap;
                    return checkstep;
                }

                if(gMap->next!=NULL){
                    //regs.ARM_r4=gMap->key;
                    gMap=gMap->next;
                }
                checkstep++;

                regs.ARM_pc+=4;
                long setreulst=ptrace(PTRACE_SETREGS, child, 0, &regs);
                if(setreulst<0){
                    logptrace("setregs",setreulst);
                }
               // LOGI("checked");

            }
            if(gMap->checkpoint){
                ptrace(PTRACE_KILL,child,0,0);
                gMap=SaveMap;
                return checkstep;
            }
            long cont=ptrace(PTRACE_CONT, child, 0, 0);
            if (  cont< 0 )
            {
                logptrace("ptrace cont",cont);
                return -1;
            }
            wait(&statloc);
        }

    }else{
        LOGE("fork error");
        return -1;
    }
    return -1;
}


void logptrace(char* func,long result)
{
    char* errormesg;
    if(result!=0){
        errormesg=strerror(errno);
        LOGE("%s ptrace error:%s",func,errormesg);
    }
    else{
        LOGI("%s ptrace result : %d",func, result);
    }
}


void turnit(char* input){

    //char buf[128];
    int index=0;
    //register int zuo =87;
    register int you ;
    //__android_log_print(ANDROID_LOG_INFO, "JNITag", "input:%s ",str);
    //u_char tmp=87;
    //u_char table[16]={87,101,49,99,111,51,116,48,108,109,101,108,50,101,86};
    for(int i=0;i<3;i++){
        for(int j=0;j<5;j++){
           // LOGI("turnit");
            k[i]=0;
            //int zuo=table[i*5+j];
            you=checksum[j%5]-(input[j%5]*k[0]+input[5+(j+1)%5]*k[1]+input[(k[0]+k[1]+k[2])*5+(j+2)%5]*k[2]);
            //if(table[i*5+j]!=checksum[j%5]-(str[j%5]*k[0]+str[5+(j+1)%5]*k[1]+str[(k[0]+k[1]+k[2])*5+(j+2)%5]*k[2])){
            __asm__ __volatile__("BKPT");
            index++;
        }
        k[i]=1;
    }
    //LOGI("turnit over");
    return ;
}