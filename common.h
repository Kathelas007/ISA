#ifndef ISA_PROJ_MAIN_H
#define ISA_PROJ_MAIN_H

#include <cstdlib>
#include <string>

enum log_level_t {
    LOG_DIS,
    LOG_VERB,
    LOG_DEB
} log_level = LOG_DIS;

class mystreambuf : public std::streambuf {
};

mystreambuf no_srtreambuf;
std::ostream no_cout(&no_srtreambuf);
#define log(x) ((x >= log_level)? std::cout : no_cout)


#endif //ISA_PROJ_MAIN_H
