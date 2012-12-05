/* 
 * File:   main.c
 * Author: kazim
 *
 * Created on June 17, 2012, 9:36 AM
 */

#include "http-logger.h"

int i=0;

int logger_service(phttp_logger_config config) {
    char *errbuf = NULL;
    bpf_u_int32 mask, net;
    pcap_t *handle = NULL;
    struct bpf_program *fp = NULL;
    int err = 0;
    int link_type;
    u_char *buf = NULL;

    errbuf = (char*) malloc(sizeof (char) *PCAP_ERRBUF_SIZE);

    syslog(LOG_INFO,"looking network on device %s\n",config->device_name);
    if (pcap_lookupnet(config->device_name, &net, &mask, errbuf) == -1) {
        syslog(LOG_ERR, "can not get network info of device %s.\nerror is %s\n", config->device_name, errbuf);
        err = 1;
        goto exit;
    }

    syslog(LOG_INFO,"opening device %s for analyzing\n",config->device_name);
    if ((handle = pcap_open_live(config->device_name, BUFSIZ, 1, 4096, errbuf)) == NULL) {
        syslog(LOG_ERR, "the device %s could not be open.\nerror is %s\n", config->device_name, errbuf);
        err = 1;
        goto exit;
    }
    
    syslog(LOG_INFO,"compiling the filter string %s\n",config->filter_string);
    fp = (struct bpf_program*) malloc(sizeof ( struct bpf_program));
    if (pcap_compile(handle, fp, config->filter_string, 0, net) == -1) {
        syslog(LOG_ERR, "can not compile the filter %s.\nerror is %s\n", config->filter_string, pcap_geterr(handle));
        err = 1;
        goto exit;
    }

    syslog(LOG_INFO,"try to set filter\n");
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
    return EXIT_SUCCESS;

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

