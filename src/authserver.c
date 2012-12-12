#include "authserver.h"

struct MHD_Daemon * auth_server_daemon = NULL;
int flag = 1;

int auth_service(phttp_logger_config config) {
    syslog(LOG_INFO, "auth server is starting\n");
    signal(SIGINT, as_signal_handler);
    signal(SIGKILL, as_signal_handler);
    signal(SIGTERM, as_signal_handler);

    auth_server_daemon = MHD_start_daemon(
            MHD_USE_THREAD_PER_CONNECTION, /* deamon thread option */
            config->auth_server_port, /* port */
            NULL, NULL, /* connection filter. accept every client */
            &answer_to_connection, /* handler function */
            config->auth_server_docdir, /* no parameter for handler */
            MHD_OPTION_END /* ending options */
            );
    if (NULL == auth_server_daemon) return 1;
    syslog(LOG_INFO, "auth server is started at port %i.\n", config->auth_server_port);
    while (flag) {
        sleep(10);
    }
    return 0;
}

void as_signal_handler(int sig) {
    if (auth_server_daemon) {
        MHD_stop_daemon(auth_server_daemon);
        flag = 0;
    }
}

int answer_to_connection(void *cls, struct MHD_Connection *connection,
        const char *url,
        const char *method, const char *version,
        const char *upload_data,
        size_t *upload_data_size, void **con_cls) {
    char *docdir = (char*) cls;
    struct MHD_Response *response;
    int ret;
    char *path;
    int fd;
    struct stat statbuf;

    if (strcmp(method, MHD_HTTP_METHOD_GET) == 0) {
        path = (char*) malloc(sizeof (char) *FILENAME_MAX);
        if (strcmp(url, "/") == 0) {
            sprintf(path, "%s%s", docdir, INDEX_PAGE);
        } else {
            sprintf(path, "%s%s", docdir, url);
        }

        fd = open(path, O_RDONLY);
        if (fd != -1) {
            fstat(fd, &statbuf);
            response = MHD_create_response_from_fd(statbuf.st_size, fd);
            ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        } else {
            response = MHD_create_response_from_buffer(strlen(ERROR_404), ERROR_404, MHD_RESPMEM_PERSISTENT);
            ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
        }
    }

    MHD_destroy_response(response);

    return ret;
}