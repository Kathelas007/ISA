#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <string>
#include <cstring>

#include "ErrorExceptions.h"
#include "DNS_Filter.h"
#include "DomainLookup.h"

using namespace std;

typedef struct {
    std::string server;
    int port = 53;
    std::string filter_file_name;
    bool verbose = false;
} dns_args_struct;

void print_help() {
    cout << "help" << endl;
    exit(0);
}

/**
 * Function checks and parses input arguments. Result is saved into args structure.
 * @param argc number of args
 * @param argv arg values
 * @param parsed args
 */
void parse_args(int argc, char **argv, dns_args_struct *args) {
    int opt;

    string port_str;
    size_t idx_stoi;

    //getting opts
    while ((opt = getopt(argc, argv, "s:p:f:")) != -1) {
        switch (opt) {
            case 's':
                args->server = optarg;
                break;
            case 'p':
                port_str = optarg;
                args->port = stoi(optarg, &idx_stoi);
                break;
            case 'f':
                args->filter_file_name = optarg;
                break;
            case 'h':
                print_help();
                break;
            case 'v':
                args->verbose = true;
                break;
            case '?':
                cerr << "Ignoring unknown option: '" << char(optopt) << "'!" << endl;
                break;
        }
    }

    // check mandatory opts
    if (args->server.empty())
        throw BadArgs_E("Server argument required");
    if (args->filter_file_name.empty())
        throw BadArgs_E("Filter file argument required.");

    //check proper port format
    if (idx_stoi != port_str.length())
        throw BadArgs_E("Port must be a number.");
    if (args->port < 0 || args->port > 65535)
        throw BadArgs_E("Port must be a number in range <0, 65535>");

}

int main(int argc, char **argv) {
    // TODO verbose mode

    dns_args_struct args;

    // parse args
    try {
        parse_args(argc, argv, &args);
    }
    catch (DNSException &e) {
        e.exit_with_msg();
    }

    // prepare dns domain searching
    DomainLookup *domain_lookup;
    try {
        domain_lookup = new DomainLookup(args.filter_file_name);
    }
    catch (DomainLoopUp_E &e) {
        e.exit_with_msg();
    }

    // get dns_server IP, IP version, listening IP
    string server_IP;
    int af;
    vector<string> name_server_IPs;

    try {
        server_IP = DNS_Filter::get_server_IP(args.server, af);
        DNS_Filter::get_name_servers_IPs(name_server_IPs, af);
    }
    catch (ServerErr_E &e) {
        e.exit_with_msg();
    }

    // check IPs for listening
    if (name_server_IPs.empty()) {
        cerr << "Can not get any ip address from /etc/resolv.conf" << endl;
        exit(10);
    }

    // init filter servers
    vector<DNS_Filter *> filters(name_server_IPs.size());
    for (u_int i = 0; i < name_server_IPs.size(); i++) {
        filters.at(i) = new DNS_Filter(domain_lookup, args.server, args.port, name_server_IPs.at(i), af);
    }

    // start dns filter dns_server for each name dns_server in /etc/resolv.conf
    vector<thread> threads_vec(name_server_IPs.size());

    // set sigkill handler in case of CTRL+C
    signal(SIGINT, DNS_Filter::sigkill_handler);

    DNS_Filter *f;
    //starting threads
    for (u_int i = 0; i < name_server_IPs.size(); i++) {
        f = filters.at(i);

        // todo catch error
        threads_vec.at(i) = thread(&DNS_Filter::start, f);
    }

    // merging threads
    for (auto &t: threads_vec) {
        t.join();
    }

    // clean up

    // delete dns filter servers
    for (auto &f: filters) {
        delete f;
    }

    delete domain_lookup;
    return 0;
}
