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
#ifdef	__cplusplus
}
#endif

#endif	/* AUTHSERVER_H */

