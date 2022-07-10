#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>

using namespace std;

void sumControl(int a, int b){
    if (a > INT_MAX - b){
        perror("integer overflow");
        exit(1);
    }   
}

void subControl(int a, int b){
	if(a <0 || b<0){
		perror("integer overflow");
		exit(-1);
	}

	if (b>a){
		perror("integer overflow");
		exit(-1);
	}
}

void IncControl(int a){
	if (a==INT_MAX){
		perror("integer overflow");
		exit(-1);
	}
}