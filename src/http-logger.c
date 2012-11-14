/* 
 * File:   main.c
 * Author: kazim
 *
 * Created on June 17, 2012, 9:36 AM
 */

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#ifdef __linux__
#include <malloc.h>
#endif
#include "http-logger.h"
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>

/*
 * 
 */
int main(int argc, char** argv) {
    pid_t sid, pid, tmp;
    int res = EXIT_FAILURE, s;


    openlog("http-logger", LOG_ODELAY, LOG_DAEMON | LOG_PID);

    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    umask(0);

    sid = setsid();
    if (sid < 0) {
        exit(EXIT_FAILURE);
    }

    if ((chdir("/")) < 0) {
        exit(EXIT_FAILURE);
    }

    signal(SIGHUP, signal_handler);
    signal(SIGTERM, signal_handler);


service_child_loop:

    pid = fork();
    if (pid == 0) {
        res = logger_service(argc, argv);
    } else {
        do {
            tmp = wait(&s);
            res = WEXITSTATUS(s);
            if (res == EXIT_FAILURE) {
                syslog(LOG_ERR, "can not run http-logger\n");
                goto exit;
            }
            sleep(1);
        } while (tmp != pid);
        goto service_child_loop;
    }


exit:
    closelog();
    return res;
}

int logger_service(int argc, char** argv) {

    char *dev, *errbuf = NULL;
    bpf_u_int32 mask, net;
    pcap_t *handle = NULL;
    struct bpf_program *fp = NULL;
    int err = 0;
    int link_type;
    u_char *buf = NULL;
    char *filter_string;
    int filter_len;
    char *conf_file;
    cfg_t * config;
    int filtersize;
    char * filter_host;
    int i, tmp;
    struct stat *stat_buf;



    errbuf = (char*) malloc(sizeof (char) *PCAP_ERRBUF_SIZE);

    argc--;
    argv++;

    if (argc <= 0) {
        syslog(LOG_ERR, "no configuration file name is given\n");
        err = 1;
        goto exit;
    }


    conf_file = *argv;

    stat_buf = (struct stat*) malloc(sizeof (struct stat));
    if (stat(conf_file, stat_buf) != 0) {
        syslog(LOG_ERR, "can not find configuration file %s\n", conf_file);
        free(stat_buf);
        err = 1;
        goto exit;
    }
    free(stat_buf);

    config = cfg_init(http_logger_conf_opts, CFGF_NONE);
    if (cfg_parse(config, conf_file) == CFG_PARSE_ERROR) {
        syslog(LOG_ERR, "can not parse configuration file\n");
        err = 1;
        goto exit;
    }

    dev = cfg_getstr(config, CFG_DEVICE_PROP);

    filter_len = strlen("(dst port 80)");
    filter_string = (char*) malloc((filter_len + 1) * sizeof (char));
    bzero(filter_string, filter_len * sizeof (char) + 1);
    strcpy(filter_string, "(dst port 80)");

    filtersize = cfg_size(config, CFG_UNLOG_HOSTS_PROP);
    for (i = 0; i < filtersize; i++) {
        char filter_buf[1024];
        filter_host = cfg_getnstr(config, CFG_UNLOG_HOSTS_PROP, i);
        tmp=sprintf(filter_buf," and (src not %s)",filter_host);
        filter_string=realloc(filter_string, (filter_len + tmp + 1) * sizeof (char));
        bzero(filter_string + filter_len, (tmp + 1) * sizeof (char));
        strcpy(filter_string + filter_len,filter_buf);
        filter_len+=tmp;
    }
    syslog(LOG_INFO,"the filter is %s\n",filter_string);

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        syslog(LOG_ERR, "can not get network info of device %s.\nerror is %s\n", dev, errbuf);
        err = 1;
        goto exit;
    }

    if ((handle = pcap_open_live(dev, BUFSIZ, 1, 4096, errbuf)) == NULL) {
        syslog(LOG_ERR, "the device %s could not be open.\nerror is %s\n", dev, errbuf);
        err = 1;
        goto exit;
    }
    fp = (struct bpf_program*) malloc(sizeof ( struct bpf_program));
    if (pcap_compile(handle, fp, filter_string, 0, net) == -1) {
        syslog(LOG_ERR, "can not compile the filter %s.\nerror is %s\n", filter_string, pcap_geterr(handle));
        err = 1;
        goto exit;
    }

    if (pcap_setfilter(handle, fp) == -1) {
        syslog(LOG_ERR, "can not attach the filter.\nerror is %s\n", pcap_geterr(handle));
        err = 1;
        goto exit;
    }

    link_type = pcap_datalink(handle);

    buf = (u_char*) malloc(sizeof (u_char)*4);
    i2c(link_type, buf);

    syslog(LOG_INFO, "the http logger configured and will start.\n");

    while (1) {
        if (pcap_loop(handle, -1, got_packet, buf) == -1) {
            syslog(LOG_ERR, "can not start the http logger.\nerror is %s\n", pcap_geterr(handle));
            sleep(1);
        }
    }
    syslog(LOG_ERR, "unexpected error.\nerror is %s\n", pcap_geterr(handle));

exit:
    if (handle != NULL) {
        pcap_close(handle);
    }
    if (errbuf) {
        free(errbuf);
    }
    if (fp) {
        free(fp);
    }
    if (buf) {
        free(buf);
    }
    if (err) {
        goto err;
    }

success:
    return (EXIT_SUCCESS);

err:
    return EXIT_FAILURE;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    //struct ethhdr *ether_hdr;
    struct ip *ip_hdr;
    struct tcphdr *tcp_hdr;
    u_char *payload;
    u_int ip_size, tcp_size, payload_size;
    int link_type;
    int offset;
    char *log_buffer, *log;
    int will_log = 0;

    c2i(link_type, args);

    if (link_type == DLT_LINUX_SLL) {
        packet += SLL_HLEN;
    } else if (link_type == DLT_EN10MB) {
        packet += ETH_HLEN;
    } else {
        syslog(LOG_ERR, "invalid link type\n");
        return;
    }


    ip_hdr = (struct ip*) (packet);
    ip_size = IP_HL(ip_hdr);
    if (ip_size < 20) {
        syslog(LOG_ERR, "invalid ip size %i\n", ip_size);
        return;
    }
    packet += ip_size;


    tcp_hdr = (struct tcphdr*) (packet);
    tcp_size = TH_OFF(tcp_hdr);
    if (tcp_size < 20) {
        syslog(LOG_ERR, "invalid tcp size %i\n", tcp_size);
        return;
    }
    packet += tcp_size;

    payload = (u_char*) packet;
    payload_size = ntohs(ip_hdr->ip_len)-(ip_size + tcp_size);

    if (payload_size == 0) {
        return;
    }

    while ((log_buffer = (char*) malloc(sizeof (char) *4096)) == NULL);

    bzero(log_buffer, 4096);
    log = log_buffer;

    offset = sprintf(log_buffer, "%s:%i ", inet_ntoa(ip_hdr->ip_src), htons(TH_SRC(tcp_hdr)));
    log_buffer += offset;
    offset = sprintf(log_buffer, " %s:%i %i", inet_ntoa(ip_hdr->ip_dst), htons(TH_DEST(tcp_hdr)),
            payload_size);
    log_buffer += offset;

    {
        char *host, *query;
        int q, h, type = 0;
        char *tmp;

        host = (char*) malloc(sizeof (char) *1024);
        query = (char*) malloc(sizeof (char) *3072);
        bzero(host, 1024);
        bzero(query, 3072);

        q = sscanf(payload, "GET %s %*s\r\n", query);
        if (q == 0) {
            type = 0;
            q = sscanf(payload, "get %s %*s\r\n", query);
        }
        if (q == 0) {
            type = 1;
            q = sscanf(payload, "POST %s %*s\r\n", query);
        }
        if (q == 0) {
            type = 1;
            q = sscanf(payload, "post %s %*s\r\n", query);
        }

        tmp = strstr(payload, "Host:");
        if (tmp == NULL) {
            tmp = strstr(payload, "host:");
        }
        if (tmp != NULL) {
            payload = tmp;
            h = sscanf(payload, "Host: %s\n", host);
            if (h == 0) {
                h = sscanf(payload, "host: %s\n", host);
            }

        }

        if (h == 1 && q == 1) {
            offset = sprintf(log_buffer, " %s %s %s", type == 0 ? "GET" : "POST", host, query);
            log_buffer += offset;
            will_log = 1;
        }
        free(host);
        free(query);
    }


    if (will_log) {
        syslog(LOG_INFO, "%s", log);

    }
    free(log);
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

