void bar(int j, int k){
};

void demo_stackframe(int a, int b, int c){
	int x = a;
	char buffer[64];
	int y = b;
	int z = c;

	bar(z,y);
}

void main(){
	demo_stackframe(1,2,3);
}
