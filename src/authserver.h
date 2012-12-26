/* 
 * File:   authserver.h
 * Author: kazim
 *
 * Created on December 5, 2012, 9:37 AM
 */

#ifndef AUTHSERVER_H
#define	AUTHSERVER_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "geninc.h"
#include <microhttpd.h>
#include <fcntl.h>

#define INDEX_PAGE      "/index.html"
#define ERROR_404       "<html><head><title>Not Found</title><body>Requested page not found.</body></html>"
#define POSTBUFFERSIZE  1024

    enum {
        HTTP_GET, HTTP_POST, HTTP_UNKNOWN
    };

    enum {
        SEND_FILE, SEND_TEXT
    };

    typedef struct __connection_data {
        int method;
        struct MHD_PostProcessor * postprocessor;
        char *username, *password;
        phttp_logger_config config;
    } connection_data, *pconnection_data;



    int auth_service(phttp_logger_config config);
    int answer_to_connection(void *cls, struct MHD_Connection *connection,
            const char *url,
            const char *method, const char *version,
            const char *upload_data,
            size_t *upload_data_size, void **con_cls);
    void as_signal_handler(int sig);
    int iterate_post(void *coninfo_cls, enum MHD_ValueKind kind, const char *key,
            const char *filename, const char *content_type,
            const char *transfer_encoding, const char *data,
            uint64_t off, size_t size);
    void request_completed(void *cls, struct MHD_Connection *connection,
            void **con_cls,
            enum MHD_RequestTerminationCode toe);
    int send_page(struct MHD_Connection *connection, char * data, int type, int response);
#ifdef	__cplusplus
}
#endif

#endif	/* AUTHSERVER_H */

