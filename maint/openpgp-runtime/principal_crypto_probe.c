/* Fixed extraction of the reviewed disposable principal probe. No account or
 * service management. The core mode checks the worker entry's inherited-zero
 * limit before a deliberate abort; it does not prove a positive-to-zero reset.
 */
#define main hidden_worker_main
#include "crypto.c"
#undef main
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>

int main(int argc, char **argv) {
 if (argc == 2 && !strcmp(argv[1], "core")) {
  struct rlimit actual;
  int result = hidden_worker_main(0, argv);
  if (result == 0 || getrlimit(RLIMIT_CORE, &actual) || actual.rlim_cur || actual.rlim_max) return 20;
  raise(SIGABRT);
  return 21;
 }
 /* This negative checks endpoint custody, before the live peer check. */
 if (argc == 4 && !strcmp(argv[3], "foreign-agent")) return confine(argv[1], argv[2], 1) ? 22 : 0;
 if (argc != 4) return 1;
 int fd = open(argv[3], O_RDONLY);
 if (fd < 3 || fcntl(fd, F_GETFD) < 0) return 2;
 close_inherited_descriptors();
 if (fcntl(fd, F_GETFD) >= 0 || errno != EBADF) return 3;
 if (!confine(argv[1], argv[2], 1)) return 4;
 if (open(argv[3], O_RDONLY) >= 0) return 5;
 pid_t child = fork();
 if (child < 0) return 6;
 if (!child) _exit(fcntl(fd, F_GETFD) < 0 && errno == EBADF ? 0 : 7);
 int status;
 if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 8;
 return 0;
}
