#include "main.h"
#include "geninc.h"
#include "authserver.h"

int main(int argc, char** argv) {
    pid_t sid, pid, tmp, pid_logger, pid_auth;
    int res, s;
    int err = 0;
    phttp_logger_config config;


    openlog("http-logger", LOG_ODELAY, LOG_DAEMON | LOG_PID);

    argc--;
    argv++;
    if (argc <= 0) {
        syslog(LOG_ERR, "no configuration file name is given\n");
        err = 1;
        goto exit;
    }

    if ((config = readconfig(argv[0])) == NULL) {
        syslog(LOG_ERR, "error at parsing configuration file\n");
        err = 1;
        goto exit;
    }

    pid = fork();
    if (pid < 0) {
        err = 1;
        goto exit;
    }
    if (pid > 0) {
        err = 1;
        goto exit;
    }

    umask(0);

    sid = setsid();
    if (sid < 0) {
        err = 1;
        goto exit;
    }

    if ((chdir("/")) < 0) {
        err = 1;
        goto exit;
    }

    signal(SIGHUP, signal_handler);
    signal(SIGTERM, signal_handler);

    pid_logger = start_service(logger_service, config);
    pid_auth = start_service(auth_service, config);
    while (1) {
        tmp = wait(&s);
        if (tmp != -1) {
            sleep(1);
            res = WEXITSTATUS(s);
            if (tmp == pid_logger) {
                syslog(LOG_ERR, "logger died with code %i. re-creating\n", res);
                pid_logger = start_service(logger_service, config);
            } else if (tmp == pid_auth) {
                syslog(LOG_ERR, "authentication died with code %i. re-creating\n", res);
                pid_auth = start_service(auth_service, config);
            }
        } else {
            syslog(LOG_ERR, "error at waiting child processes. error: %i.\n",
                    strerror(errno));
        }
    }



exit:
    closelog();
    if (err) {
        return EXIT_FAILURE;
    } else {
        return EXIT_SUCCESS;
    }
}

pid_t start_service(start_service_func ssf, phttp_logger_config config) {
    pid_t pid;
    int res;
    pid = fork();
    if (pid == 0) {
        res = ssf(config);
        exit(res);
    } else {
        return pid;
    }
}

void signal_handler(int sig) {
    switch (sig) {
        case SIGHUP:
            break;
        case SIGTERM:
            exit(0);
            break;
    }
}

phttp_logger_config readconfig(char * filename) {
    char *filter_string;
    int filter_len;
    cfg_t * config;
    int filtersize;
    char * filter_host;
    int i, tmp;
    struct stat *stat_buf;
    int err = 0;
    phttp_logger_config hl_config = NULL;

    stat_buf = (struct stat*) malloc(sizeof (struct stat));
    if (stat(filename, stat_buf) != 0) {
        syslog(LOG_ERR, "can not find configuration file %s\n", filename);
        free(stat_buf);
        err = 1;
        goto exit;
    }
    free(stat_buf);

    config = cfg_init(http_logger_conf_opts, CFGF_NONE);
    if (cfg_parse(config, filename) == CFG_PARSE_ERROR) {
        syslog(LOG_ERR, "can not parse configuration file\n");
        err = 1;
        goto exit;
    }

    hl_config = (phttp_logger_config) malloc(sizeof (http_logger_config));

    hl_config->device_name = cfg_getstr(config, CFG_DEVICE_PROP);
    hl_config->auth_server_port = cfg_getint(config, CFG_AUTHSERVER_PORT_PROP);

    filter_len = strlen("(dst port 80)");
    filter_string = (char*) malloc((filter_len + 1) * sizeof (char));
    bzero(filter_string, filter_len * sizeof (char) + 1);
    strcpy(filter_string, "(dst port 80)");

    filtersize = cfg_size(config, CFG_UNLOG_HOSTS_PROP);
    for (i = 0; i < filtersize; i++) {
        char filter_buf[1024];
        filter_host = cfg_getnstr(config, CFG_UNLOG_HOSTS_PROP, i);
        tmp = sprintf(filter_buf, " and (src not %s)", filter_host);
        filter_string = realloc(filter_string, (filter_len + tmp + 1) * sizeof (char));
        bzero(filter_string + filter_len, (tmp + 1) * sizeof (char));
        strcpy(filter_string + filter_len, filter_buf);
        filter_len += tmp;
    }
    hl_config->filter_string = filter_string;
    syslog(LOG_INFO, "the filter is %s\n", filter_string);
exit:
    if (err) {
        if (hl_config) {
            free(hl_config);
        }
        return NULL;
    } else {
        return hl_config;
    }
}
