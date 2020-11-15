/**
 * author: xmusko00
 * email: xmusko00@vutbr.cz
 *
 * file: common.cpp
 * description: basic logger
 */


#ifndef ISA_PROJ_MAIN_H
#define ISA_PROJ_MAIN_H

#include <cstdlib>
#include <string>

enum log_level_t {
    LOG_DIS,
    LOG_VERB,
    LOG_DEB
};

extern log_level_t log_level;

class mystreambuf;

extern mystreambuf no_srtreambuf;
extern std::ostream no_cout;
#define logg(x) ((x <= log_level)? std::cout : no_cout)

#endif //ISA_PROJ_MAIN_H
