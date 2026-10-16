/* Source-only Dovecot 2.3.21.1 final IMAP publication hook. */
#include "config.h"
#include "imap-common.h"
#include "mail-user.h"
#include "master-service.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifndef __OpenBSD__
#error "OSMAP IMAP publication requires qualified OpenBSD kernel peer ABI"
#endif
/* The matching native SDK compile proves the ctypes contract against installed
 * machine types too; retained header text alone does not prove these widths. */
_Static_assert(SOL_SOCKET == 0xffff && SO_PEERCRED == 0x1022, "peer constants");
_Static_assert(sizeof(uid_t) == 4 && sizeof(gid_t) == 4 && sizeof(pid_t) == 4 &&
    sizeof(socklen_t) == 4 && sizeof(struct sockpeercred) == 12, "peer sizes");
_Static_assert(offsetof(struct sockpeercred, uid) == 0 &&
    offsetof(struct sockpeercred, gid) == 4 && offsetof(struct sockpeercred, pid) == 8,
    "peer offsets");

const char *osmap_imap_epoch_plugin_version = DOVECOT_ABI_VERSION;
const char osmap_imap_epoch_plugin_binary_dependency[] = "imap";
static imap_client_created_func_t *previous_created;
/* No config, environment or request can enable this source qualification gate.
 * Current client_limit1/service_count1/hibernate0, matching installed SDK/module
 * custody, exact peer inspector and actual race must precede signed admission. */
static const bool native_publication_qualified = FALSE;
static const char endpoint[] = "/var/run/osmap-account/imap-publication.sock";

static double monotonic_now(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
        i_fatal("OSMAP IMAP publication unavailable");
    return ts.tv_sec + ts.tv_nsec / 1000000000.0;
}

static bool bounded_text(const char *value, const char *alphabet, size_t maximum)
{
    size_t n;
    if (value == NULL || (n = strlen(value)) == 0 || n > maximum)
        return FALSE;
    for (; *value != '\0'; value++)
        if (strchr(alphabet, *value) == NULL)
            return FALSE;
    return TRUE;
}

static bool wait_fd(int fd, short events, double end)
{
    struct pollfd pfd = { fd, events, 0 };
    for (;;) {
        double left = end - monotonic_now();
        if (left <= 0)
            return FALSE;
        int millis = (int)(left * 1000);
        if (millis < 1)
            return FALSE;
        int result = poll(&pfd, 1, millis);
        if (result < 0 && errno == EINTR)
            continue;
        return result > 0 && (pfd.revents & events) != 0 &&
            (pfd.revents & (POLLERR | POLLNVAL)) == 0 && monotonic_now() < end;
    }
}

static bool publish(struct client *client)
{
    struct sockaddr_un address;
    char request[512], response[4];
    size_t sent = 0, received = 0;
    double end = monotonic_now() + 0.5;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0), error = 0;
    socklen_t error_size = sizeof(error);
    bool accepted = FALSE;
    if (fd < 0)
        return FALSE;
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0 || fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
        goto done;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
#ifdef __OpenBSD__
    address.sun_len = sizeof(address);
#endif
    if (sizeof(endpoint) > sizeof(address.sun_path))
        goto done;
    memcpy(address.sun_path, endpoint, sizeof(endpoint));
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0 &&
        errno != EINPROGRESS)
        goto done;
    if (!wait_fd(fd, POLLOUT, end) ||
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_size) < 0 ||
        error_size != sizeof(error) || error != 0)
        goto done;
#ifdef __OpenBSD__
    uid_t peer_uid;
    gid_t peer_gid;
    if (getpeereid(fd, &peer_uid, &peer_gid) < 0 || peer_uid != 0 || peer_gid != 0)
        goto done;
#else
    goto done; /* No emulated kernel-peer or cross-platform native claim. */
#endif
    int size = snprintf(request, sizeof(request), "PUBLISH\t%s\t%s\t%d\t%ld\n",
        client->user->username, client->user->session_id,
        client->user->conn.ssl_secured ? 1 : 0, (long)getpid());
    if (size <= 0 || (size_t)size >= sizeof(request))
        goto done;
    while (sent < (size_t)size) {
        if (!wait_fd(fd, POLLOUT, end))
            goto done;
        ssize_t n = write(fd, request + sent, size - sent);
        if (n < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        if (n <= 0)
            goto done;
        sent += n;
    }
    while (received < sizeof(response)) {
        if (!wait_fd(fd, POLLIN, end))
            goto done;
        ssize_t n = read(fd, response + received, sizeof(response) - received);
        if (n < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        if (n == 0) {
            accepted = received == 3 && memcmp(response, "OK\n", 3) == 0 &&
                monotonic_now() < end;
            goto done;
        }
        if (n < 0)
            goto done;
        received += n;
    }
done:
    close(fd);
    return accepted;
}

static void osmap_client_created(struct client **clientp)
{
    if (previous_created != NULL)
        previous_created(clientp);
    if (clientp == NULL || *clientp == NULL)
        return;
    struct client *client = *clientp;
    /* This per-user server-owned field is absent for unrelated accounts. No
     * IPC, root lookup, failure or process exit is added to that path. */
    const char *managed = mail_user_plugin_getenv(client->user, "osmap_epoch_managed");
    if (managed == NULL || strcmp(managed, "yes") != 0)
        return;
    if (master_service_get_client_limit(master_service) != 1 || imap_client_count != 1) {
        /* This configuration can never qualify. Avoid terminating an unrelated
         * multiplexed client if trusted administration drifts after admission.
         * Closing this socket/ostream prevents its tagged success write. */
        shutdown(client->fd_in, SHUT_RDWR);
        if (client->fd_out != client->fd_in)
            shutdown(client->fd_out, SHUT_RDWR);
        client_disconnect(client, "OSMAP IMAP publication unavailable");
        return;
    }
    if (!native_publication_qualified ||
        client->unhibernated || client->hibernated || client->destroyed ||
        !bounded_text(client->user->username,
            "abcdefghijklmnopqrstuvwxyz0123456789@._+-", 254) ||
        !bounded_text(client->user->session_id,
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+_=.-", 128) ||
        client->user->service == NULL || strcmp(client->user->service, "imap") != 0 || !publish(client))
        i_fatal("OSMAP IMAP publication unavailable");
    /* Returning permits the tagged reply. The exact process is now visible
     * under the same lock used by mutation, so a later writer must kick it and
     * retain that lock until zero-session readback. */
}

void osmap_imap_epoch_plugin_init(struct module *module ATTR_UNUSED)
{
    previous_created = imap_client_created_hook_set(osmap_client_created);
}

void osmap_imap_epoch_plugin_deinit(void)
{
    imap_client_created_hook_set(previous_created);
}
