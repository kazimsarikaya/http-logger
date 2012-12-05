#include "authserver.h"

int auth_service(phttp_logger_config config){
    syslog(LOG_INFO,"auth server is starting\n");
    sleep(30);
    return 0;
}