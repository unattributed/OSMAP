#define main inventory_worker_main
#include "inventory.c"
#undef main
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
int main(int argc,char **argv){
 if(argc!=3||access(argv[2],R_OK)||!valid_home(argv[1])||!confine(argv[1]))return 1;
 /* Both current and forked process must fail to open the existing outsider. */
 if(open(argv[2],O_RDONLY)>=0)return 2;
 pid_t pid=fork();if(pid<0)return 3;if(!pid){
  char *args[]={INVENTORY_ENGINE,"--no-options","--homedir",argv[1],"--batch","--no-auto-check-trustdb","--no-default-keyring","--keyring",argv[2],"--list-keys",NULL};
  execv(INVENTORY_ENGINE,args);_exit(99);
 }
 int status;if(waitpid(pid,&status,0)!=pid||!WIFEXITED(status)||!WEXITSTATUS(status)||WEXITSTATUS(status)==99)return 5;
 char file[4096];if(snprintf(file,sizeof(file),"%s/pubring.kbx",argv[1])>=(int)sizeof(file))return 6;
 int fd=open(file,O_RDONLY);if(fd<0)return 7;close(fd);
 fd=open(file,O_WRONLY);if(fd>=0){close(fd);return 8;}
 return 0;
}
