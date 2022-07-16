#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "constants.h"

using namespace std;

struct user{
    string username;

};

user* users[constants::TOT_USERS];
unsigned int n_users=0;