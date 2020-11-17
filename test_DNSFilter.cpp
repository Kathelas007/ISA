/**
 * author: xmusko00
 * email: xmusko00@vutbr.cz
 *
 * file: test_DNSFilterp.cpp
 */


#include <iostream>
#include <cstdlib>
#include <fstream>
#include <vector>
#include <string>

#include "DNSFilter.h"
#include "ErrorExceptions.h"
#include "DomainLookup.h"

using namespace std;

DNSFilter *df;
DomainLookup *dl;
vector<bool (*)()> test_functions;

bool test_is_IPv4() {
    return DNSFilter::is_IPv4("127.0.0.1");
}

bool test_is_not_IPv4() {
    return !(DNSFilter::is_IPv4("127.0.0") or DNSFilter::is_IPv4("2001:4860:4860::8888") or
             DNSFilter::is_IPv4("google.com"));
}

bool test_is_IPv6() {
    return DNSFilter::is_IPv6("2001:4860:4860::8888");
}

bool test_is_not_IPv6() {
    return !(DNSFilter::is_IPv6("2001:4860:4860") or DNSFilter::is_IPv6("127.0.0.1") or
             DNSFilter::is_IPv6("google.com"));
}

bool test_domain_to_IP() {
    string dom = "google.com";
    DNSFilter::domain_to_IP(dom);
    return ("172.217.23.238" == dom);
}

bool test_get_server_ip() {
    int af = 2;
    return ("172.217.23.238" == DNSFilter::get_server_IP("google.com", af));
}

void setUp() {
    ofstream filter_file;
    filter_file.open("test_filter.fil", ios::out | ios::trunc);
    filter_file << "org\n"
                   "facebook.com\n"
                   "12345.domainname.google.net\n";

    filter_file.close();

    dl = new DomainLookup("test_filter.fil");
    df = new DNSFilter(dl, "8.8.8.8", 1234, 2);

    test_functions.push_back(test_is_IPv4);
    test_functions.push_back(test_is_not_IPv4);
    test_functions.push_back(test_is_IPv6);
    test_functions.push_back(test_is_not_IPv6);
    test_functions.push_back(test_domain_to_IP);
    test_functions.push_back(test_get_server_ip);
}

void make_test() {
    cout << "\n\nDNS Filter Test\n\n";

    int OK = 0;
    int FAILED = 0;
    for (int i = 0; i < test_functions.size(); i++) {
        cout << "Test " << i + 1 << ": ";
        if (test_functions[i]()) {
            cout << "OK" << endl;
            OK++;
        } else {
            cout << "FAILED" << endl;
            FAILED++;
        }
    }

    cout << "\n" << "Summary:\t" << OK << "/" << OK + FAILED << " succeeded\n" << endl;
}

void TearDown() {
    delete df;
    delete dl;
}

int main(int argc, char **argv) {
    setUp();
    make_test();
    TearDown();
}