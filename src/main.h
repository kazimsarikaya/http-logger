/* 
 * File:   main.h
 * Author: kazim
 *
 * Created on December 5, 2012, 9:41 AM
 */

#ifndef MAIN_H
#define	MAIN_H

#ifdef	__cplusplus
extern "C" {
#endif

#include "geninc.h"
    
    
    void signal_handler(int sig);
    phttp_logger_config readconfig(char * filename);


    cfg_opt_t http_logger_conf_opts[] = {
        CFG_STR(CFG_DEVICE_PROP, CFG_DEVICE_DEFAULT, CFGF_NONE),
        CFG_STR_LIST(CFG_UNLOG_HOSTS_PROP, CFG_UNLOG_HOSTS_DEFUALT, CFGF_NONE),
        CFG_INT(CFG_AUTHSERVER_PORT_PROP,CFG_AUTHSERVER_PORT_DEFAULT,CFGF_NONE),
        CFG_STR(CFG_AUTHSERVER_DOCDIR_PROP,CFG_AUTHSERVER_DOCDIR_DEFAULT,CFGF_NONE),
        CFG_STR(CFG_USERNAME_FIELD_PROP,CFG_USERNAME_FIELD_DEFAULT,CFGF_NONE),
        CFG_STR(CFG_PASSWORD_FIELD_PROP,CFG_PASSWORD_FIELD_DEFAULT,CFGF_NONE),
        CFG_END()
    };

    typedef pid_t (*start_service_func) (phttp_logger_config config) ;
    pid_t start_service(start_service_func ssf, phttp_logger_config config);
    
    extern int logger_service(phttp_logger_config config);
    extern int auth_service(phttp_logger_config config);
    
#ifdef	__cplusplus
}
#endif

#endif	/* MAIN_H */

