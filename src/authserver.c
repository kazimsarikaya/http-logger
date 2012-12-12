#include "authserver.h"

struct MHD_Daemon * auth_server_daemon = NULL;
int flag=1;

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
            NULL, /* no parameter for handler */
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
        flag=0;
    }
}

int answer_to_connection(void *cls, struct MHD_Connection *connection,
        const char *url,
        const char *method, const char *version,
        const char *upload_data,
        size_t *upload_data_size, void **con_cls) {
    const char *page = "<html><body>Hello, browser!</body></html>";
    struct MHD_Response *response;
    int ret;

    response = MHD_create_response_from_buffer(strlen(page),
            (void*) page, MHD_RESPMEM_PERSISTENT);
    ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);

    return ret;
}