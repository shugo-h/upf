#include "utlt_debug.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdlib.h>

#include "logger.h"
#include "utlt_lib.h"
#include "utlt_list.h"

// TODO : Need to use buffer written by ourself
#define MAX_SIZE_OF_BUFFER 32768

unsigned int reportCaller = 0;
static int logLevel = LOG_INFO;

static void __lowerString(char *output, const char *input) {
    size_t n = strlen(input);
    size_t i;

    for (i = 0; i < n; i++) {
        output[i] = tolower(input[i]);
    }
    output[i] = '\0';
}

Status UTLT_SetLogLevel(const char *level) {
    if (UpfUtilLog_SetLogLevel(UTLT_CStr2GoStr(level))) {
        char *lwrLevel = malloc(strlen(level)+1);
        if (!lwrLevel)
            return STATUS_ERROR;
        __lowerString(lwrLevel, level);

        if (!strcmp(lwrLevel, "panic"))
            logLevel = LOG_PANIC;
        else if (!strcmp(lwrLevel, "fatal"))
            logLevel = LOG_FATAL;
        else if (!strcmp(lwrLevel, "error"))
            logLevel = LOG_ERROR;
        else if (!strcmp(lwrLevel, "warning"))
            logLevel = LOG_WARNING;
        else if (!strcmp(lwrLevel, "info"))
            logLevel = LOG_INFO;
        else if (!strcmp(lwrLevel, "debug"))
            logLevel = LOG_DEBUG;
        else if (!strcmp(lwrLevel, "trace"))
            logLevel = LOG_TRACE;
        else {
            free(lwrLevel);
            return STATUS_ERROR;
        }

        free(lwrLevel);
        return STATUS_OK;
    }
    else
        return STATUS_ERROR;
}

Status UTLT_SetReportCaller(unsigned int flag) {
    if (reportCaller >= REPORTCALLER_MAX) {
        reportCaller = 0;
        return STATUS_ERROR;
    }

    reportCaller = flag;
    return STATUS_OK;
}

typedef struct {
    ListHead node;
    pthread_t tid;
    char buffer[MAX_SIZE_OF_BUFFER];
} logBufNode;

static ListHead logBufList;

int UTLT_LogPrint(int level, const char *filename, const int line, 
                  const char *funcname, const char *fmt, ...) {

    unsigned int cnt, vspCnt;
    if (level > logLevel) return status;

    // initialize logBufList if it is not initialized yet
    if (!ListNext(&logBufList)) ListHeadInit(&logBufList);

    // find the log buffer for the caller thread
    pthread_t tid = pthread_self();
    char *buffer;
    logBufList *it, *next;
    ListForEachSafe(it, next, &logBufList) {
        if (it->tid == tid) {
            buffer = it->buffer;
            break;
        }
    }

    // allocate a new buffer to the caller thread if the buffer is not found
    if (!buffer) {
        logBufNode *node = malloc(sizeof(logBufNode));
        if (!node) return STATUS_ERROR;
        node->tid = tid;
        ListInsert(node, &logBufList);
        buffer = node->buffer;
    }

    size_t buflen = sizeof((logBufNode *)NULL)->buffer);
    va_list vl;
    va_start(vl, fmt);
    vspCnt = vsnprintf(buffer, buflen, fmt, vl);
    if (vspCnt < 0) {
        fprintf(stderr, "vsnprintf in UTLT_LogPrint error : %s\n", strerror(errno));
        status = STATUS_ERROR;
    } else if (vspCnt == 0) {
        status = STATUS_OK;
    }
    va_end(vl);
    if (status != STATUS_OK) goto unlockReturn;

    if (reportCaller == REPORTCALLER_TRUE) {
        cnt = snprintf(buffer + vspCnt, buflen - vspCnt, " (%s:%d %s)", filename, line, funcname);
        if (cnt < 0) {
            fprintf(stderr, "sprintf in UTLT_LogPrint error : %s\n", strerror(errno));
            return STATUS_ERROR;
        }
    }

    switch(level) {
        case 0 :
            UpfUtilLog_Panicln(UTLT_CStr2GoStr(buffer));
            break;
        case 1 :
            UpfUtilLog_Fatalln(UTLT_CStr2GoStr(buffer));
            break;
        case 2 :
            UpfUtilLog_Errorln(UTLT_CStr2GoStr(buffer));
            break;
        case 3 :
            UpfUtilLog_Warningln(UTLT_CStr2GoStr(buffer));
            break;
        case 4 :
            UpfUtilLog_Infoln(UTLT_CStr2GoStr(buffer));
            break;
        case 5 :
            UpfUtilLog_Debugln(UTLT_CStr2GoStr(buffer));
            break;
        case 6 :
            UpfUtilLog_Traceln(UTLT_CStr2GoStr(buffer));
            break;
        default :
            fprintf(stderr, "The log level %d is out of range.\n", level);
            return STATUS_ERROR;
    }

    return STATUS_OK;
}

const char *UTLT_StrStatus(Status status) {
    switch(status) {
        case STATUS_OK :
            return "status OK";
        case STATUS_ERROR :
            return "status error";
        case STATUS_EAGAIN :
            return "status eagain";
        default :
            return "status unknown";
    }
}
