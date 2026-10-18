/* Source-only Dovecot 2.3.21.1 final IMAP publication hook. */
#include "config.h"
#include "imap-common.h"
#include "mail-user.h"
#include "master-service.h"
#include "ioloop.h"
#include "module-context.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
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
static MODULE_CONTEXT_DEFINE_INIT(osmap_imap_module, &imap_module_register);
struct osmap_epoch_client {
    union imap_module_context module_ctx;
    struct client *client;
    struct io *control_io;
    int control_fd;
};
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

static void control_close(struct osmap_epoch_client *context)
{
    io_remove(&context->control_io);
    if (context->control_fd >= 0) {
        close(context->control_fd);
        context->control_fd = -1;
    }
}

static void osmap_client_destroy(struct client *client, const char *reason)
{
    struct osmap_epoch_client *context =
        MODULE_CONTEXT_REQUIRE(client, osmap_imap_module);
    void (*next_destroy)(struct client *, const char *) =
        context->module_ctx.super.destroy;
    context->client = NULL;
    control_close(context);
    next_destroy(client, reason);
    /* The chained destroy frees client->pool, including context. */
}

static void control_input(struct osmap_epoch_client *context)
{
    char byte;
    ssize_t n = read(context->control_fd, &byte, 1);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return;
    /* Any byte, EOF or permanent error invalidates this lifetime lease.
     * Shutdown precedes control EOF so the helper cannot observe closure while
     * this client still has a usable transport. Never signal a numeric PID. */
    struct client *client = context->client;
    if (client != NULL && !client->destroyed) {
        shutdown(client->fd_in, SHUT_RDWR);
        if (client->fd_out != client->fd_in)
            shutdown(client->fd_out, SHUT_RDWR);
    }
    control_close(context);
    if (client != NULL && !client->destroyed)
        client_disconnect(client, "OSMAP IMAP lifetime authorization ended");
}

static int publish(struct client *client)
{
    struct sockaddr_un address;
    char request[512], response[3];
    size_t sent = 0, received = 0;
    double end = monotonic_now() + 0.5;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0), error = 0;
    socklen_t error_size = sizeof(error);
    bool rights_sent = FALSE;
    if (fd < 0)
        return -1;
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
    if (client->fd_in < 0 || client->fd_out < 0)
        goto done;
    int descriptors[2] = { client->fd_in, client->fd_out };
    unsigned int descriptor_count = client->fd_in == client->fd_out ? 1 : 2;
    int size = snprintf(request, sizeof(request),
        "PUBLISH2\t%s\t%s\t%d\t%ld\tfd_in=%d\tfd_out=%d\tfds=%u\n",
        client->user->username, client->user->session_id,
        client->user->conn.ssl_secured ? 1 : 0, (long)getpid(),
        client->fd_in, client->fd_out, descriptor_count);
    if (size <= 0 || (size_t)size >= sizeof(request))
        goto done;
    while (sent < (size_t)size) {
        if (!wait_fd(fd, POLLOUT, end))
            goto done;
        ssize_t n;
        if (!rights_sent) {
            union {
                struct cmsghdr alignment;
                unsigned char bytes[CMSG_SPACE(sizeof(descriptors))];
            } ancillary;
            struct iovec vector = { request + sent, (size_t)size - sent };
            struct msghdr message;
            memset(&message, 0, sizeof(message));
            memset(&ancillary, 0, sizeof(ancillary));
            message.msg_iov = &vector;
            message.msg_iovlen = 1;
            message.msg_control = ancillary.bytes;
            message.msg_controllen = CMSG_SPACE(descriptor_count * sizeof(int));
            struct cmsghdr *control = CMSG_FIRSTHDR(&message);
            control->cmsg_level = SOL_SOCKET;
            control->cmsg_type = SCM_RIGHTS;
            control->cmsg_len = CMSG_LEN(descriptor_count * sizeof(int));
            memcpy(CMSG_DATA(control), descriptors, descriptor_count * sizeof(int));
            n = sendmsg(fd, &message, 0);
        } else {
            n = write(fd, request + sent, size - sent);
        }
        if (n < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        if (n <= 0)
            goto done;
        rights_sent = TRUE;
        sent += n;
    }
    while (received < sizeof(response)) {
        if (!wait_fd(fd, POLLIN, end))
            goto done;
        ssize_t n = read(fd, response + received, sizeof(response) - received);
        if (n < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        if (n <= 0)
            goto done;
        received += n;
    }
    if (memcmp(response, "OK\n", sizeof(response)) == 0 && monotonic_now() < end) {
        char extra;
        ssize_t n;
        do {
            n = recv(fd, &extra, 1, MSG_PEEK);
        } while (n < 0 && errno == EINTR && monotonic_now() < end);
        /* No EOF handshake: the authenticated helper owns this channel for
         * the entire client lifetime. Extra bytes/early close fail closed. */
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) &&
            monotonic_now() < end)
            return fd;
    }
done:
    close(fd);
    return -1;
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
        client->user->service == NULL || strcmp(client->user->service, "imap") != 0)
        i_fatal("OSMAP IMAP publication unavailable");
    int control_fd = publish(client);
    if (control_fd < 0)
        i_fatal("OSMAP IMAP publication unavailable");
    struct osmap_epoch_client *context =
        p_new(client->pool, struct osmap_epoch_client, 1);
    context->module_ctx.super = client->v;
    context->client = client;
    context->control_fd = control_fd;
    MODULE_CONTEXT_SET(client, osmap_imap_module, context);
    client->v.destroy = osmap_client_destroy;
    context->control_io = io_add(control_fd, IO_READ, control_input, context);
    /* Returning permits the tagged reply. The exact process is now visible
     * under the same lock used by mutation. The root helper owns duplicates of
     * the exact transport and requires this lifetime channel's closure after
     * shutdown, rather than relying on a reusable PID. */
}

void osmap_imap_epoch_plugin_init(struct module *module ATTR_UNUSED)
{
    previous_created = imap_client_created_hook_set(osmap_client_created);
}

void osmap_imap_epoch_plugin_deinit(void)
{
    imap_client_created_hook_set(previous_created);
}
