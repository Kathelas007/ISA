#include <cstring>
#include <utility>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <cstdio>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <thread>

#include <cstring>

#include <csignal>
#include <bitset>

#include<netinet/ip.h>
#include<netinet/ip6.h>

#include <cstdio>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <cstring>
#include <unistd.h>

#include "DNS_Filter.h"
#include "ErrorExceptions.h"
#include "DomainLookup.h"

#include "common.h"

#if defined(_GLIBCXX_HAS_GTHREADS) && defined(_GLIBCXX_USE_C99_STDINT_TR1)
#endif

using namespace std;

bool DNS_Filter::run = true;
//shared_mutex DNS_Filter::run_mutex{};
vector<int> DNS_Filter::sock_fds{};


// ******************* STATIC METHODS ***************************************

void DNS_Filter::sigkill_handler(int signum) {
    logg(LOG_VERB) << "\nQuiting ..." << endl << flush;

    // stop run
//    DNS_Filter::run_mutex.lock();
    DNS_Filter::run = false;
//    DNS_Filter::run_mutex.unlock();

    // shut down sockets
    for (auto sck: DNS_Filter::sock_fds) {
        shutdown(sck, SHUT_RDWR);
    }
}

// **** domain, ips handling

bool DNS_Filter::is_IPv4(string ip) {
    unsigned char buf[sizeof(struct in_addr)];
    return (inet_pton(AF_INET, ip.c_str(), buf) == 1);
}

bool DNS_Filter::is_IPv6(string ip) {
    unsigned char buf[sizeof(struct in6_addr)];
    return (inet_pton(AF_INET6, ip.c_str(), buf) == 1);
}

bool DNS_Filter::domain_to_IP(std::string &str) {
    struct hostent *host = gethostbyname(str.c_str());
    if (host) {
        str = inet_ntoa(*(struct in_addr *) host->h_addr_list[0]);
        return true;
    }
    return false;
}

string DNS_Filter::get_server_IP(string server, int &af) {
    // its IPv4 address
    if (DNS_Filter::is_IPv4(server)) {
        af = AF_INET;
        return server;
    }
        // its IPv6 address
    else if (DNS_Filter::is_IPv6(server)) {
        af = AF_INET6;
        return server;
    }

    // its domain name
    if (domain_to_IP(server)) {

        if (DNS_Filter::is_IPv4(server)) {
            af = AF_INET;
            return server;
        }
            // its IPv6 address
        else if (DNS_Filter::is_IPv6(server)) {
            af = AF_INET6;
            return server;
        }
    }
    throw ServerErr_E("Not valid dns_server IP address or domain name.");
}

// ******** non STATIC METHODS ************************

DNS_Filter::DNS_Filter(DomainLookup *domain_lookup_m, std::string dns_server_ip,
                       int port, int af) {
    this->domain_lookup = domain_lookup_m;
    this->port = port;
    this->dns_server = std::move(dns_server_ip);
    this->ip_version = af;
}

int DNS_Filter::retransmit_ipv4(u_char *buffer, int &buffer_len) {
    struct sockaddr_in dns_server_addr{}, localhost_addr{};

    memset(&dns_server_addr, 0, sizeof(dns_server_addr));
    memset(&localhost_addr, 0, sizeof(localhost_addr));

    in_addr dns_server_net_ord{};
    inet_aton(this->dns_server.c_str(), &dns_server_net_ord);

    memcpy(&dns_server_addr.sin_addr, &dns_server_net_ord.s_addr, sizeof(dns_server_addr.sin_addr));
    dns_server_addr.sin_port = htons(53);
    dns_server_addr.sin_family = this->ip_version;

    int sock_fd;
    if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        logg(LOG_VERB) << "Can not create socket to dns server." << endl;
        return false;
    }

    timeval tv{};
    tv.tv_sec = 2;

    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(timeval));

    if (!sendto(sock_fd, buffer, buffer_len, MSG_CONFIRM,
                (const struct sockaddr *) &dns_server_addr, sizeof(dns_server_addr))) {
        logg(LOG_VERB) << "Can not send msg_p to dns server." << endl;
        return false;
    }

    int n;
    socklen_t length = sizeof(dns_server_addr);
    if ((n = recvfrom(sock_fd, buffer, BUFFER_LEN, 0, (struct sockaddr *) &dns_server_addr, &length)) < 0) {
        logg(LOG_VERB) << "Did not received msg_p from dns server." << endl;
        return false;
    }
    buffer[n] = '\0';
    logg(LOG_DEB) << "DNS resp len: " << n << endl;
    buffer_len = n;

    close(sock_fd);
    return true;

}

int DNS_Filter::retransmit_ipv6(u_char *buffer, int &buffer_len) {
    struct sockaddr_in6 dns_server_addr{}, localhost_addr{};

    memset(&dns_server_addr, 0, sizeof(dns_server_addr));
    memset(&localhost_addr, 0, sizeof(localhost_addr));

    in6_addr dns_server_net_ord{};
    inet_pton(this->ip_version, this->dns_server.c_str(), &dns_server_net_ord);

    memcpy(&dns_server_addr.sin6_addr, &dns_server_net_ord, sizeof(dns_server_addr.sin6_addr));
    dns_server_addr.sin6_port = htons(53);
    dns_server_addr.sin6_family = this->ip_version;

    int sock_fd;
    if ((sock_fd = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
        logg(LOG_VERB) << "Can not create socket to dns server." << endl;
        return false;
    }

    timeval tv{};
    tv.tv_sec = 2;

    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(timeval));

    if (!sendto(sock_fd, buffer, buffer_len, MSG_CONFIRM,
                (const struct sockaddr *) &dns_server_addr, sizeof(dns_server_addr))) {
        logg(LOG_VERB) << "Can not send msg_p to dns server." << endl;
        return false;
    }

    int n;
    socklen_t length = sizeof(dns_server_addr);
    if ((n = recvfrom(sock_fd, buffer, BUFFER_LEN, 0, (struct sockaddr *) &dns_server_addr, &length)) < 0) {
        logg(LOG_VERB) << "Did not received msg_p from dns server." << endl;
        return false;
    }
    buffer[n] = '\0';
    logg(LOG_DEB) << "DNS resp len: " << n << endl;
    buffer_len = n;

    close(sock_fd);
    return true;
}

int DNS_Filter::retransmit(u_char *buffer, int &buffer_len) {
    // client communicating with outer dns server

    if (this->ip_version == AF_INET)
        return this->retransmit_ipv4(buffer, buffer_len);
    else
        return this->retransmit_ipv6(buffer, buffer_len);
}

void DNS_Filter::set_dns_refused(u_char *buffer, int &buff_len) {
    dns_header_struct *dns_header;
    dns_header = (dns_header_struct *) buffer;
    dns_header->reply_code = 5;
}

void DNS_Filter::set_dns_notimplemented(u_char *buffer, int &buff_len) {
    dns_header_struct *dns_header;
    dns_header = (dns_header_struct *) buffer;
    dns_header->reply_code = 4;
}


void DNS_Filter::get_response(u_char *buffer, int &n) {
    string domain;
    int type, class_t;
    bool response;
    int dns_header_len = 12;

    if (!DNS_Filter::process_dns_body((u_char *) (&buffer[dns_header_len]), domain, type, class_t)) {
        if (type != 1) {
            // no A record
            this->set_dns_notimplemented(buffer, n);
        } else {
            // domain is zero length
            this->set_dns_refused(buffer, n);
        }
        return;
    }

    if (!DNS_Filter::process_dns_header((&buffer[0]), response)) {
        if (response) {
            // not a query
            this->set_dns_refused(buffer, n);
        } else {
            // bad question count
            this->set_dns_notimplemented(buffer, n);
        }
        return;
    }

    if (this->domain_lookup->searchDomain(domain)) {
        // refused
        //filtered
        this->set_dns_refused(buffer, n);
        logg(LOG_VERB) << "Request to domain " << domain << " filtered." << endl;
    } else {
        this->retransmit(buffer, n);
    }
}

void DNS_Filter::sent_response(u_char *buffer, int &buffer_len, sockaddr_in client_addr) {

}

void DNS_Filter::start_ipv4() {
    int sock_fd;
    u_char buffer[BUFFER_LEN];

    sockaddr_in server_addr{}, client_addr{};

    memset(&server_addr, 0, sizeof(server_addr));
    memset(&client_addr, 0, sizeof(client_addr));

    server_addr.sin_family = this->ip_version;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(this->port);

    if ((sock_fd = socket(this->ip_version, SOCK_DGRAM, 0)) == -1)
        throw DNS_Filter_E("Can not open socket.");

    DNS_Filter::sock_fds.push_back(sock_fd);

    if (bind(sock_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) == -1) {
        cout << strerror(errno) << endl;
        throw DNS_Filter_E("Can not bind port to socket.");
    }

    socklen_t length = sizeof(server_addr);
    int n;
    while (((n = recvfrom(sock_fd, buffer, BUFFER_LEN, 0, (struct sockaddr *) &client_addr, &length)) >= 0)
           && DNS_Filter::still_run()) {

        logg(LOG_VERB) << endl;
        logg(LOG_DEB) << "Request from: " << inet_ntoa(client_addr.sin_addr) << endl;
        logg(LOG_DEB) << "DNS req len: " << n << endl;

        this->get_response(buffer, n);

        if (!sendto(sock_fd, buffer, n, MSG_DONTWAIT,
                    (const struct sockaddr *) &client_addr, sizeof(client_addr))) {
            logg(LOG_VERB) << "Can not send dns response to client." << endl;
        }
    }
    close(sock_fd);
}

void DNS_Filter::start_ipv6() {
    int sock_fd;
    u_char buffer[BUFFER_LEN];

    sockaddr_in6 server_addr{}, client_addr{};

    memset(&server_addr, 0, sizeof(server_addr));
    memset(&client_addr, 0, sizeof(client_addr));

    server_addr.sin6_family = this->ip_version;
    server_addr.sin6_addr = IN6ADDR_ANY_INIT;
    server_addr.sin6_port = htons(this->port);

    if ((sock_fd = socket(this->ip_version, SOCK_DGRAM, 0)) == -1)
        throw DNS_Filter_E("Can not open socket.");

    DNS_Filter::sock_fds.push_back(sock_fd);

    if (bind(sock_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) == -1) {
        cout << strerror(errno) << endl;
        throw DNS_Filter_E("Can not bind port to socket.");
    }

    socklen_t length = sizeof(server_addr);
    int n;
    while (((n = recvfrom(sock_fd, buffer, BUFFER_LEN, 0, (struct sockaddr *) &client_addr, &length)) >= 0)
           && DNS_Filter::still_run()) {

        logg(LOG_VERB) << endl;
        char buf6[INET6_ADDRSTRLEN];
        inet_ntop(this->ip_version, &(client_addr.sin6_addr), buf6, sizeof(buf6));
        logg(LOG_DEB) << "Request from: " << buf6 << endl;
        logg(LOG_DEB) << "DNS req len: " << n << endl;

        this->get_response(buffer, n);

        if (!sendto(sock_fd, buffer, n, MSG_DONTWAIT,
                    (const struct sockaddr *) &client_addr, sizeof(client_addr))) {
            logg(LOG_VERB) << "Can not send back dns response to client." << endl;
        }
    }
    close(sock_fd);
}


void DNS_Filter::start() {
    // local dns filter server
    if (this->ip_version == AF_INET)
        this->start_ipv4();
    else
        this->start_ipv6();
}


bool DNS_Filter::still_run() {
    bool run = DNS_Filter::run;

    return run;
}

bool DNS_Filter::process_dns_header(u_char *dns_start, bool &response) {
    dns_header_struct *dns_header;

    dns_header = (dns_header_struct *) (dns_start);

    short id, count;
    memcpy(&id, &(dns_header->id), 2);
    memcpy(&count, &(dns_header->q_count), 2);

    id = htons(id);
    count = htons(count);

    response = dns_header->response;

    logg(LOG_DEB) << "qc: " << count << endl;

    return htons(count) != 1;
}

bool DNS_Filter::process_dns_body(u_char *dns_body, std::string &domain, int &type, int &class_t) {
    int octet_id = 0;
    auto len_octet = (unsigned int) *dns_body;

    while (len_octet != 0) {
        domain.append((char *) (dns_body + octet_id + 1), len_octet);
        domain.append(1, '.');
        octet_id += len_octet + 1;
        len_octet = (u_char) *(dns_body + octet_id);
    }
    domain.erase(domain.length() - 1, 1);

    auto *type_us = (unsigned short *) (dns_body + octet_id + 1);
    auto *class_us = (unsigned short *) (dns_body + octet_id + 3);

    type = htons(*type_us);
    class_t = htons(*class_us);

    logg(LOG_DEB) << "domain: " << domain << endl;
    logg(LOG_DEB) << "type: " << type << endl << "class: " << class_t << endl;

    if (domain.length() <= 0 || type != 1)
        return false;

    return true;
}










