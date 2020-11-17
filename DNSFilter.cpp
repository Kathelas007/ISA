/**
 * author: xmusko00
 * email: xmusko00@vutbr.cz
 *
 * file: DNSFilter.cpp
 */

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdlib>
#include <netdb.h>

#include "DNSFilter.h"
#include "ErrorExceptions.h"
#include "DomainLookup.h"

#include "logger.h"

#if defined(_GLIBCXX_HAS_GTHREADS) && defined(_GLIBCXX_USE_C99_STDINT_TR1)
#endif

using namespace std;

bool DNSFilter::run = true;
vector<int> DNSFilter::sock_fds{};

// **************************************************************************
// ******************* STATIC METHODS ***************************************
// **************************************************************************

/**
 * Called in case of CTRL+C. Server gets info, that it should not run anzmore.
 * Server can be sytuated is in blocking recvfrom, threrefor shut down is called on socket.
 * @param signum
 */
void DNSFilter::sigterm_handler(int signum) {
    logg(LOG_VERB) << "\nQuiting ..." << endl << flush;

    // stop run
    DNSFilter::run = false;

    // shut down sockets
    for (auto sck: DNSFilter::sock_fds) {
        shutdown(sck, SHUT_RDWR);
    }
}

// **************** domain, ips handling ***********************************

/**
 * Check if given string is ipv4
 * @param ip
 * @return result
 */
bool DNSFilter::is_IPv4(string ip) {
    unsigned char buf[sizeof(struct in_addr)];
    return (inet_pton(AF_INET, ip.c_str(), buf) == 1);
}

/**
 * Check if given string is ipv6
 * @param ip
 * @return result
 */
bool DNSFilter::is_IPv6(string ip) {
    unsigned char buf[sizeof(struct in6_addr)];
    return (inet_pton(AF_INET6, ip.c_str(), buf) == 1);
}

/**
 * Converts domain name to ipv4
 * @param str
 * @return result
 */
bool DNSFilter::domain_to_IP(std::string &str) {
    struct hostent *host = gethostbyname(str.c_str());
    if (host) {
        str = inet_ntoa(*(struct in_addr *) host->h_addr_list[0]);
        return true;
    }
    return false;
}

/**
 * If server is domain name, fnc converts it to ipv4.
 * Otherwise finds out ip version
 * @param server: domain of ip
 * @param af: ip version
 * @return: ip
 */
string DNSFilter::get_server_IP(string server, int &af) {
    // its IPv4 address
    if (DNSFilter::is_IPv4(server)) {
        af = AF_INET;
        return server;
    }
        // its IPv6 address
    else if (DNSFilter::is_IPv6(server)) {
        af = AF_INET6;
        return server;
    }

    // its domain name
    if (domain_to_IP(server)) {

        if (DNSFilter::is_IPv4(server)) {
            af = AF_INET;
            return server;
        }
            // its IPv6 address
        else if (DNSFilter::is_IPv6(server)) {
            af = AF_INET6;
            return server;
        }
    }
    throw BadIpDomain_E("Not valid dns_server IP address or domain name.");
}

// **************************************************************************
// ***************** non STATIC METHODS *************************************
// **************************************************************************

/**
 * Initiation
 * @param domain_lookup_m: pointer to Domain Class, that check if domains are filtered
 * @param dns_server_ip: dns server to retransmit requests
 * @param port: port to listen on
 * @param af: ip version
 */
DNSFilter::DNSFilter(DomainLookup *domain_lookup_m, std::string dns_server_ip,
                     int port, int af) {
    this->domain_lookup = domain_lookup_m;
    this->port = port;
    this->dns_server = std::move(dns_server_ip);
    this->ip_version = af;
}

DNSFilter::~DNSFilter() {
    DNSFilter::sigterm_handler(0);
}


/**
 * Methon creates ipv4 client, that query outside dns server
 * @param buffer: dns payload
 * @param buffer_len: length of buffer
 * @return succes or fail
 */
int DNSFilter::retransmit_ipv4(unsigned char *buffer, int &buffer_len) {
    struct sockaddr_in dns_server_addr{}, localhost_addr{};

    memset(&dns_server_addr, 0, sizeof(dns_server_addr));
    memset(&localhost_addr, 0, sizeof(localhost_addr));

    in_addr dns_server_net_ord{};
    inet_aton(this->dns_server.c_str(), &dns_server_net_ord);

    // fill sockaddr_in
    memcpy(&dns_server_addr.sin_addr, &dns_server_net_ord.s_addr, sizeof(dns_server_addr.sin_addr));
    dns_server_addr.sin_port = htons(53);
    dns_server_addr.sin_family = this->ip_version;

    // open socket
    int sock_fd;
    if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        logg(LOG_VERB) << "Can not create socket to dns server." << endl;
        return false;
    }

    timeval tv{};
    tv.tv_sec = 2;

    // set timeout 2 s
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(timeval));

    //sent request
    if (!sendto(sock_fd, buffer, buffer_len, 0,
                (const struct sockaddr *) &dns_server_addr, sizeof(dns_server_addr))) {
        logg(LOG_VERB) << "Can not send msg_p to dns server." << endl;
        return false;
    }

    //receive answer
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

/**
 * Methon creates ipv6 client, that query outside dns server
 * @param buffer: dns payload, filled with answer after receive
 * @param buffer_len: length of buffer
 * @return succes or fail
 */
int DNSFilter::retransmit_ipv6(unsigned char *buffer, int &buffer_len) {
    struct sockaddr_in6 dns_server_addr{}, localhost_addr{};

    memset(&dns_server_addr, 0, sizeof(dns_server_addr));
    memset(&localhost_addr, 0, sizeof(localhost_addr));

    in6_addr dns_server_net_ord{};
    inet_pton(this->ip_version, this->dns_server.c_str(), &dns_server_net_ord);

    // fill in6_addr
    memcpy(&dns_server_addr.sin6_addr, &dns_server_net_ord, sizeof(dns_server_addr.sin6_addr));
    dns_server_addr.sin6_port = htons(53);
    dns_server_addr.sin6_family = this->ip_version;

    // open socket
    int sock_fd;
    if ((sock_fd = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
        logg(LOG_VERB) << "Can not create socket to dns server." << endl;
        return false;
    }

    timeval tv{};
    tv.tv_sec = 2;

    //set timeout
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(timeval));

    // send request
    if (!sendto(sock_fd, buffer, buffer_len, 0,
                (const struct sockaddr *) &dns_server_addr, sizeof(dns_server_addr))) {
        logg(LOG_VERB) << "Can not send msg_p to dns server." << endl;
        return false;
    }

    // receive answer
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

/**
 * Sent dns request as client to dns server
 * @param buffer: dns payload, filled with answer after receive
 * @param buffer_len: length of buffer
 * @return
 */
int DNSFilter::retransmit(unsigned char *buffer, int &buffer_len) {
    // client communicating with outer dns server

    if (this->ip_version == AF_INET)
        return this->retransmit_ipv4(buffer, buffer_len);
    else
        return this->retransmit_ipv6(buffer, buffer_len);
}

void DNSFilter::set_dns_refused(unsigned char *buffer, int &buff_len) {
    dns_header_struct *dns_header;
    dns_header = (dns_header_struct *) buffer;
    dns_header->reply_code = 5;
    dns_header->response = 1;
}

void DNSFilter::set_dns_notimplemented(unsigned char *buffer, int &buff_len) {
    dns_header_struct *dns_header;
    dns_header = (dns_header_struct *) buffer;
    dns_header->reply_code = 4;
    dns_header->response = 1;
}

/**
 * Fnc analyzes dns request.
 * Request can be retransmitted to dns server or error response can be set.
 * @param buffer: dns request
 * @param n: length of request
 */
void DNSFilter::get_response(unsigned char *buffer, int &n) {
    string domain;
    int type, class_t;
    bool response;
    int dns_header_len = 12;

    if (!DNSFilter::process_dns_body((unsigned char *) (&buffer[dns_header_len]), domain, type, class_t)) {
        if (type != 1) {
            // no A record
            this->set_dns_notimplemented(buffer, n);
            logg(LOG_DEB) << "Not A record" << endl;
        } else {
            // domain is zero length
            this->set_dns_refused(buffer, n);
            logg(LOG_DEB) << "Domain is zero lenght" << endl;
        }
        return;
    }

    if (!DNSFilter::process_dns_header((&buffer[0]), response)) {
        if (response) {
            // not a query
            this->set_dns_refused(buffer, n);
            logg(LOG_DEB) << "Not a query" << endl;
        } else {
            // bad question count
            this->set_dns_notimplemented(buffer, n);
            logg(LOG_DEB) << "Bad question count" << endl;
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

void DNSFilter::sent_response(unsigned char *buffer, int &buffer_len, sockaddr_in client_addr) {

}

/**
 * Fnc starts ipv4 server, that catches dns requests
 */
void DNSFilter::start_ipv4() {
    int sock_fd;
    unsigned char buffer[BUFFER_LEN];

    sockaddr_in server_addr{}, client_addr{};

    memset(&server_addr, 0, sizeof(server_addr));
    memset(&client_addr, 0, sizeof(client_addr));

    //fill sockaddr_in
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(this->port);

    //open socket
    if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        throw Socket_E("Can not open socket.");

    DNSFilter::sock_fds.push_back(sock_fd);

    // bind to specified port
    if (bind(sock_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) == -1) {
        cout << strerror(errno) << endl;
        throw Socket_E("Can not bind port to socket.");
    }

    // start server and catch dns requests
    socklen_t length = sizeof(server_addr);
    int n;
    pid_t pid;
    while (((n = recvfrom(sock_fd, buffer, BUFFER_LEN, 0, (struct sockaddr *) &client_addr, &length)) >= 0)
           && DNSFilter::still_run()) {

        logg(LOG_VERB) << endl;
        logg(LOG_DEB) << "Request from: " << inet_ntoa(client_addr.sin_addr) << endl;
        logg(LOG_DEB) << "DNS req len: " << n << endl;

        if ((pid = fork()) > 0) {  // this is parent process
            continue;
        } else if (pid == 0) { // child process
            this->get_response(buffer, n);

            if (!sendto(sock_fd, buffer, n, MSG_DONTWAIT,
                        (const struct sockaddr *) &client_addr, sizeof(client_addr))) {
                logg(LOG_VERB) << "Can not send dns response to client." << endl;
            }
            exit(0); // exit child
        } else {
            logg(LOG_DEB) << "Can not create fork.";
        }


    }
    close(sock_fd);
}

/**
 * Fnc starts ipv6 server, that catches dns requests
 */
void DNSFilter::start_ipv6() {
    int sock_fd;
    unsigned char buffer[BUFFER_LEN];

    sockaddr_in6 server_addr{}, client_addr{};

    memset(&server_addr, 0, sizeof(server_addr));
    memset(&client_addr, 0, sizeof(client_addr));

    // fill sockaddr_in6
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_addr = IN6ADDR_ANY_INIT;
    server_addr.sin6_port = htons(this->port);

    if ((sock_fd = socket(AF_INET6, SOCK_DGRAM, 0)) == -1)
        throw Socket_E("Can not open socket.");

    DNSFilter::sock_fds.push_back(sock_fd);

    // bind to specific port
    if (bind(sock_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) == -1) {
        cout << strerror(errno) << endl;
        throw Socket_E("Can not bind port to socket.");
    }

    // start dns server capturing ds requests
    socklen_t length = sizeof(server_addr);
    int n;
    while (((n = recvfrom(sock_fd, buffer, BUFFER_LEN, 0, (struct sockaddr *) &client_addr, &length)) >= 0)
           && DNSFilter::still_run()) {

        logg(LOG_VERB) << endl;
        char buf6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(client_addr.sin6_addr), buf6, sizeof(buf6));
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

/**
 * Start dns server
 */
void DNSFilter::start() {
    // local dns filter server

    if (this->ip_version == AF_INET)
        this->start_ipv4();
    else
        this->start_ipv6();
}

/**
 * Check if filter server is still allowed to run
 * @return
 */
bool DNSFilter::still_run() {
    return DNSFilter::run;
}

/**
 * Analyze dns header
 * @param dns_start
 * @param response
 * @return
 */
bool DNSFilter::process_dns_header(unsigned char *dns_start, bool &response) {
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

/**
 * Analyze dns body
 * @param dns_body
 * @param domain
 * @param type
 * @param class_t
 * @return
 */
bool DNSFilter::process_dns_body(unsigned char *dns_body, std::string &domain, int &type, int &class_t) {
    int octet_id = 0;
    auto len_octet = (unsigned int) *dns_body;

    // get domain
    while (len_octet != 0) {
        domain.append((char *) (dns_body + octet_id + 1), len_octet);
        domain.append(1, '.');
        octet_id += len_octet + 1;
        len_octet = (unsigned char) *(dns_body + octet_id);
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











