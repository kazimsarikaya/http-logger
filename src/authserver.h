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

    int auth_service(phttp_logger_config config);
    int answer_to_connection (void *cls, struct MHD_Connection *connection, 
                          const char *url, 
                          const char *method, const char *version, 
                          const char *upload_data, 
                          size_t *upload_data_size, void **con_cls);
    void as_signal_handler(int sig);
#ifdef	__cplusplus
}
#endif

#endif	/* AUTHSERVER_H */

