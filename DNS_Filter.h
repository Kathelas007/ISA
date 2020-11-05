//
// Created by awesome on 26.10.20.
//

#ifndef ISA_PROJ_DNS_FILTER_H
#define ISA_PROJ_DNS_FILTER_H

#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string>
#include <netdb.h>
#include <string>
#include <fstream>
#include <shared_mutex>
#include <mutex>

#include <vector>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <vector>

#include "DomainLookup.h"

class DNS_Filter {
public:
    explicit DNS_Filter(DomainLookup *domain_lookup_m, std::string dns_server_ip, int port,
                        std::string filter_server_ip, int af);

    static bool is_IPv4(std::string ip);

    static bool is_IPv6(std::string ip);

    static bool domain_to_IP(std::string &str);

    static std::string get_server_IP(std::string, int &);

    static void get_name_servers_IPs(std::vector<std::string> &IPs, int af);

    static void sigkill_handler(int signum);

    void start();

protected:
    DomainLookup *domain_lookup;
    int port;
    std::string dns_server;
    std::string filter_server;
    int ip_version;

    static bool run;
    static std::shared_mutex run_mutex;

    void start_capturing_responses();

    void start_capturing_requests();

    char err_buf[PCAP_ERRBUF_SIZE];

    pcap_t *get_pcap_handler();

    void set_pcap_filter(pcap_t *, bpf_u_int32) const;

    static void request_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

    bool process_ip(u_char *ip_start, int &length);

    bool process_udp(u_char *udp_start, int &dst_port);

    bool process_dns_header(u_char *dns_start, bool &response);

    bool process_dns_body(u_char *dns_body, std::string &domain, int &type, int &class_t);
};


#pragma pack(push, 1)
typedef struct {
    unsigned short int src_port;
    unsigned short int dst_port;
    unsigned short int len;
    unsigned short int checksum;
} udp_header_struct;

#pragma pack(push, 1)
typedef struct {
    unsigned short id; // identification number

# if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    unsigned char recursion_desired: 1;
    unsigned char truncation: 1;
    unsigned char authoritative_answer: 1;
    unsigned char opcode: 4; // opcode standart == 0
    unsigned char response: 1; // query == 0 or sersponse

    unsigned char reply_code: 4;
    unsigned char reserved: 3;
    unsigned char recursion_available: 1;
# else
    unsigned char response: 1; // query == 0 or sersponse
    unsigned char opcode: 4; // opcode standart == 0
    unsigned char authoritative_answer: 1;
    unsigned char truncation: 1;
    unsigned char recursion_desired: 1;

    unsigned char recursion_available: 1;
    unsigned char reserved: 3;
    unsigned char reply_code: 4;
#endif
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
} dns_header_struct;


#endif //ISA_PROJ_DNS_FILTER_H
