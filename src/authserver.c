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
            config, /* send config to the methods */
            MHD_OPTION_NOTIFY_COMPLETED, /* handler for every connection termination */
            &request_completed,
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
    phttp_logger_config config = (phttp_logger_config) cls;
    int ret;
    char *path;
    pconnection_data conn_data;


    path = (char*) malloc(sizeof (char) *FILENAME_MAX);

    if (*con_cls == NULL) {
        conn_data = (pconnection_data) malloc(sizeof (connection_data));
        bzero(conn_data, sizeof (connection_data));
        conn_data->config = config;
        if (strcmp(method, MHD_HTTP_METHOD_GET) == 0) {
            conn_data->method = HTTP_GET;
        } else if (strcmp(method, MHD_HTTP_METHOD_POST) == 0) {
            conn_data->method = HTTP_POST;
            conn_data->postprocessor = MHD_create_post_processor(connection, POSTBUFFERSIZE,
                    iterate_post, (void*) conn_data);
        } else {
            conn_data->method = HTTP_UNKNOWN;
        }
        * con_cls = (void*) conn_data;
        return MHD_YES;
    } else {
        conn_data = (pconnection_data) * con_cls;
    }

    if (strcmp(method, MHD_HTTP_METHOD_GET) == 0) {
        if (strcmp(url, "/") == 0) {
            sprintf(path, "%s%s", config->auth_server_docdir, INDEX_PAGE);
        } else {
            sprintf(path, "%s%s", config->auth_server_docdir, url);
        }
        ret = send_page(connection, path, SEND_FILE, MHD_HTTP_OK);
    } else if (strcmp(method, MHD_HTTP_METHOD_POST) == 0) {
        if (*upload_data_size != 0) {
            MHD_post_process(conn_data->postprocessor, upload_data, *upload_data_size);
            *upload_data_size = 0;
            return MHD_YES;
        } else {
            syslog(LOG_INFO, "the post data is [%s,%s]\n", conn_data->username, conn_data->password);
        }
    }


    return ret;
}

void request_completed(void *cls, struct MHD_Connection *connection,
        void **con_cls,
        enum MHD_RequestTerminationCode toe) {
    pconnection_data conn_data = (pconnection_data) * con_cls;
    if (conn_data == NULL) {
        return;
    }

    if (conn_data->method == HTTP_POST) {
        MHD_destroy_post_processor(conn_data->postprocessor);
        if (conn_data->username) {
            free(conn_data->username);
        }
        if (conn_data->password) {
            free(conn_data->password);
        }
    }
    free(conn_data);
    *con_cls = NULL;
}

int iterate_post(void *coninfo_cls, enum MHD_ValueKind kind, const char *key,
        const char *filename, const char *content_type,
        const char *transfer_encoding, const char *data,
        uint64_t off, size_t size) {
    pconnection_data conn_data = (pconnection_data) coninfo_cls;
    if (strcmp(key, conn_data->config->username_field) == 0) {
        conn_data->username = (char*) malloc(sizeof (char) *(size + 1));
        strncpy(conn_data->username, data, size);
    } else if (strcmp(key, conn_data->config->password_field) == 0) {
        conn_data->password = (char*) malloc(sizeof (char) *(size + 1));
        strncpy(conn_data->password, data, size);
    }
    if (conn_data->password != NULL && conn_data->username != NULL) {
        return MHD_NO;
    }
    return MHD_YES;
}

int send_page(struct MHD_Connection *connection, char * data, int type, int rc) {
    int ret = -1;
    int fd;
    struct stat statbuf;
    struct MHD_Response *response;
    
    if (type == SEND_FILE) {

        fd = open(data, O_RDONLY);
        if (fd != -1) {
            fstat(fd, &statbuf);
            response = MHD_create_response_from_fd(statbuf.st_size, fd);
            ret = MHD_queue_response(connection, rc, response);
        } else {
            return send_page(connection,ERROR_404,SEND_TEXT,MHD_HTTP_NOT_FOUND);
        }

    } else if (type == SEND_TEXT) {
        response = MHD_create_response_from_buffer(strlen(data), data, MHD_RESPMEM_PERSISTENT);
        ret = MHD_queue_response(connection, rc, response);

    }
    MHD_destroy_response(response);
    return ret;
}