/* GPGME engine adapter. No shell, user configuration, network lookup, agent
 * autostart, interactive Pinentry, weak outgoing cipher or hash selection. */
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>
#ifndef CRYPTO_GPG
#define CRYPTO_GPG "/usr/local/bin/gpg"
#endif
int main(int argc, char **argv) {
 struct rlimit core = {0, 0};
 if (setrlimit(RLIMIT_CORE, &core) || argc < 1 || argc > 256) return 1;
 const char *fixed[] = {CRYPTO_GPG, "--no-options", "--no-autostart", "--rfc4880",
  "--batch", "--pinentry-mode", "error", "--no-auto-key-retrieve",
  "--auto-key-locate", "clear", "--no-auto-check-trustdb",
  "--cipher-algo", "AES256", "--digest-algo", "SHA256",
  "--compress-algo", "none", "--no-emit-version", "--no-comments"};
 size_t count = sizeof(fixed) / sizeof(fixed[0]);
 char **args = calloc(count + (size_t)argc + 1, sizeof(*args));
 if (!args) return 1;
 for (size_t i = 0; i < count; i++) args[i] = (char *)fixed[i];
 for (int i = 1; i < argc; i++) args[count + (size_t)i - 1] = argv[i];
 execv(CRYPTO_GPG, args);
 return 1;
}
