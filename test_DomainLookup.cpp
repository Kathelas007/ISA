/**
 * author: xmusko00
 * email: xmusko00@vutbr.cz
 *
 * file: test_DomainLookup.cpp
 */


#include <iostream>
#include <cstdlib>
#include <fstream>
#include <vector>
#include <string>

#include "DomainLookup.h"
#include "ErrorExceptions.h"

using namespace std;

DomainLookup *dl;
std::vector<bool (*)(string &)> test_functions;

bool test_bad_filter_file(string &msg) {
    try {
        DomainLookup tdl = DomainLookup("");
    }
    catch (DomainLoopUp_E &e) {
        return true;
    }
    return false;
}

bool test_not_filtered(string &msg) {
    return !dl->searchDomain("seznam.cz");
}

bool test_not_filtered_middle(string &msg) {
    return !dl->searchDomain("facebook.cz");
}

bool test_not_filtered_start(string &msg) {
    return !dl->searchDomain("test.org");
}

bool test_not_filtered_not_subdom(string &msg) {
    return !dl->searchDomain("5.domainname.google.net");
}

bool test_filtered_full(string &msg) {
    return dl->searchDomain("facebook.com");
}

bool test_filtered_subdomain(string &msg) {
    return dl->searchDomain("aaa.12345.domainname.google.net");
}

bool test_filtered_root_domain(string &msg) {
    return dl->searchDomain("org");
}


void setUp() {
    ofstream filter_file;
    filter_file.open("test_filter.fil", ios::out | ios::trunc);
    filter_file << "org\n"
                   "facebook.com\n"
                   "12345.domainname.google.net\n";

    filter_file.close();

    dl = new DomainLookup("test_filter.fil");

    test_functions.push_back(test_bad_filter_file);
    test_functions.push_back(test_not_filtered);
    test_functions.push_back(test_not_filtered_middle);
    test_functions.push_back(test_not_filtered_start);
    test_functions.push_back(test_not_filtered_not_subdom);
    test_functions.push_back(test_filtered_full);
    test_functions.push_back(test_filtered_subdomain);
    test_functions.push_back(test_filtered_root_domain);

}

void make_test() {
    cout << "\n\nDomain Lookup Test\n\n";

    string msg{};
    int OK = 0;
    int FAILED = 0;
    for (int i = 0; i < test_functions.size(); i++) {
        cout << "Test " << i+1 << ": ";
        if (test_functions[i](msg)) {
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
    delete dl;
}

int main(int argc, char **argv) {
    setUp();
    make_test();
    TearDown();
}