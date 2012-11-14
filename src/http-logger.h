/* 
 * File:   http_logger.h
 * Author: kazim
 *
 * Created on June 17, 2012, 9:37 AM
 */

#ifndef HTTP_LOGGER_H
#define	HTTP_LOGGER_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#ifdef __linux__
#include <netinet/ether.h>
#endif
#ifdef __APPLE__
#include <net/ethernet.h>
#endif
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <confuse.h>


#ifdef __APPLE__
#define ETH_HLEN        sizeof(struct ether_header)
#endif

    void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
    void signal_handler(int sig);
    int logger_service(int argc, char** argv);

#define SLL_HLEN        16

#define IP_HL(ip)		((ip)->ip_hl*4) 

#ifdef __linux__
#define TH_OFF(th)              ((th)->doff*4)
#define TH_SRC(th)              ((th)->source)
#define TH_DEST(th)             ((th)->dest)
#endif
#ifdef __APPLE__
#define TH_OFF(th)              ((th)->th_off*4)
#define TH_SRC(th)              ((th)->th_sport)
#define TH_DEST(th)             ((th)->th_dport)
#endif
   
#define CFG_DEVICE_PROP "device"    
#define CFG_UNLOG_HOSTS_PROP "unlog_hosts"
    
cfg_opt_t http_logger_conf_opts[]={
    CFG_STR(CFG_DEVICE_PROP,"eth0",CFGF_NONE),
    CFG_STR_LIST(CFG_UNLOG_HOSTS_PROP,"{}",CFGF_NONE),
    CFG_END()
};    
    
    
#define i2c(i,ca)               ca[0]=(i & 0xff); ca[1]=((i>>8) & 0xff); ca[2]=((i>>16) & 0xff); ca[3]=((i>>24)& 0xff); 
#define c2i(i,ca)               i=ca[0] | (ca[1]<<8) | (ca[2]<<16) | (ca[3]<<24)

#ifdef	__cplusplus
}
#endif

#endif	/* HTTP_LOGGER_H */

