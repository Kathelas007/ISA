/**
 * author: xmusko00
 * email: xmusko00@vutbr.cz
 *
 * file: ErrorException.cpp
 */

#ifndef ISA_PROJ_ERROREXCEPTIONS_H
#define ISA_PROJ_ERROREXCEPTIONS_H

#include <iostream>
#include <exception>

class DNSException : public std::exception {
protected:
    int code{};
    std::string msg_p{};

public:
    void exit_with_code() const noexcept {
        exit(code);
    }
};

class BadArgs_E : public DNSException {
public:
    BadArgs_E() {
        this->code = 1;
        std::cerr << "Incorrect arguments." << std::endl;
    }

    explicit BadArgs_E(std::string msg) {
        this->code = 1;
        std::cerr << msg << std::endl;
    }
};

class DomainLoopUp_E : public DNSException {
public:
    explicit DomainLoopUp_E(std::string msg) {
        this->code = 2;
        std::cerr << msg << std::endl;
    }
};

class Socket_E : public DNSException {

public:
    explicit Socket_E(std::string msg) {
        this->code = 3;
        std::cerr << msg << std::endl;
    }
};

class BadIpDomain_E : public DNSException {
public:
    explicit BadIpDomain_E(std::string msg) {
        this->code = 4;
        std::cerr << msg << std::endl;
    }
};



#endif //ISA_PROJ_ERROREXCEPTIONS_H
