#ifndef ISA_PROJ_ERROREXCEPTIONS_H
#define ISA_PROJ_ERROREXCEPTIONS_H

#include <iostream>
#include <exception>

class DNSException : public std::exception {
protected:
    int code{};
    std::string msg;

public:
    const char *what() noexcept {
        return msg.c_str();
    }

    void exit_with_msg() noexcept {
        std::cerr << msg.c_str() << std::endl;
        exit(code);
    }
};

class BadArgs_E : public DNSException {
public:
    BadArgs_E() {
        this->code = 1;
        this->msg = "Incorrect arguments.";
    }

    explicit BadArgs_E(std::string msg) {
        this->code = 1;
        this->msg = msg;
    }
};

class ServerErr_E : public DNSException {
public:
    explicit ServerErr_E(std::string msg) {
        this->code = 1;
        this->msg = msg;
    }
};


#endif //ISA_PROJ_ERROREXCEPTIONS_H
