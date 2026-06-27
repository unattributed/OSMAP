/*
 * OSMAP V12 OpenPGP helper compile scaffold.
 *
 * This file is intentionally limited to compile and link proof against GPGME.
 * It must not implement OpenPGP message operations.
 */
#include <gpgme.h>
#include <stdio.h>

int main(void) {
    const char *version = gpgme_check_version(NULL);
    if (version == NULL) {
        fputs("gpgme unavailable\n", stderr);
        return 2;
    }
    puts("osmap-openpgp-helper compile scaffold linked with gpgme");
    return 0;
}
