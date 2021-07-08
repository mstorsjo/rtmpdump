#include "rtmp.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>

int main() {


	RTMP_HOOK hook;
	RTMP *rtmp = (RTMP*) malloc(sizeof(RTMP));
        
	RTMP_LogSetLevel(RTMP_LOGDEBUG);

	RTMP_Init(rtmp);
        RTMP_Init_Hook(rtmp, &hook);
        

	printf("rtmp->hook: %p, hook: %p\n", rtmp->hook, &hook);
	return 0;
}
