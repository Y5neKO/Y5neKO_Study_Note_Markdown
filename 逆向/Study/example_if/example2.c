#include <stdio.h>

int login(int username, int password){
	int flag = 0;
	if(username == 123){
		if(password == 456){
			flag = 1;
			printf("login success");
		}else{
			printf("password error");
		}
	}else{
		printf("username error");
	}

	return flag;
}


int main(){
	int login_flag = login(123, 457);
	return 0;
}
