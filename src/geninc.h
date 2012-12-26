/* 
 * File:   geninc.h
 * Author: kazim
 *
 * Created on December 5, 2012, 9:51 AM
 */

#ifndef GENINC_H
#define	GENINC_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#ifdef __linux__
#include <malloc.h>
#endif
#include <confuse.h>
#define __USE_GNU
#include <pthread.h>
#include <errno.h>


#define CFG_DEVICE_PROP "device"   
#define CFG_DEVICE_DEFAULT "eth0"
#define CFG_UNLOG_HOSTS_PROP "unlog_hosts"
#define CFG_UNLOG_HOSTS_DEFUALT "{}" 
#define CFG_AUTHSERVER_PORT_PROP "authserver_port"
#define CFG_AUTHSERVER_PORT_DEFAULT 8080
#define CFG_AUTHSERVER_DOCDIR_PROP "authserver_docdir"
#define CFG_AUTHSERVER_DOCDIR_DEFAULT "/usr/share/http-logger/docdir"
#define CFG_USERNAME_FIELD_PROP "username_field"   
#define CFG_USERNAME_FIELD_DEFAULT "username"
#define CFG_PASSWORD_FIELD_PROP "password_field"   
#define CFG_PASSWORD_FIELD_DEFAULT "password"

    typedef struct __config {
        char * device_name;
        char * filter_string;
        int auth_server_port;
        char * auth_server_docdir;
        char * username_field;
        char * password_field;
    } http_logger_config, *phttp_logger_config;

#ifdef	__cplusplus
}
#endif

#endif	/* GENINC_H */

