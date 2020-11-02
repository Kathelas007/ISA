//
// Created by root on 02.11.20.
//

#ifndef ISA_PROJ_DOMAINLOOKUP_H
#define ISA_PROJ_DOMAINLOOKUP_H

#include <vector>
#include <string>
#include <unordered_map>

#include <bits/stdc++.h>

class DomainLookup {
protected:
    std::unordered_set<std::string> domains;

    // stackoverflow
    static inline void ltrim(std::string &s) {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(),
                                        std::not1(std::ptr_fun<int, int>(std::isspace))));
    }

    static inline void rtrim(std::string &s) {
        s.erase(std::find_if(s.rbegin(), s.rend(),
                             std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
    }

    static inline void trim(std::string &s) {
        ltrim(s);
        rtrim(s);
    }

public:
    DomainLookup(std::string);

    void searchDomain(std::string);
};


#endif //ISA_PROJ_DOMAINLOOKUP_H
