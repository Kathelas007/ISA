//
// Created by root on 02.11.20.
//

#include <iostream>
#include <fstream>

#include "DomainLookup.h"
#include "ErrorExceptions.h"

using namespace std;

DomainLookup::DomainLookup(string file_name) {
    ifstream f_handler;
    f_handler.open(file_name.c_str());

    if (!f_handler.is_open())
        throw DomainLoopUp_E("Can not open filter file.");

    string line;
    while (!f_handler.eof()) {
        getline(f_handler, line);
        DomainLookup::trim(line);
        if (!line.empty() and line[0] != '#') {
            this->domains.insert(line);
        }
    }

    f_handler.close();
}

void DomainLookup::searchDomain(std::string domain) {
    vector<string> splitted_domain;
    int pos;
    string token;
    while ((pos = domain.find('.')) != std::string::npos) {
        token = domain.substr(0, pos);
        cout << token << " ";
        splitted_domain.push_back(token);
        domain.erase(0, pos + 1);
    }
    cout << endl;

    if (this->domains.count(domain))
        return;
}
