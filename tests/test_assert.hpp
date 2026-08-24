#pragma once

#include <cstdlib>
#include <iostream>
#include <string>

#define WB_CHECK(cond)                                                                           \
    do {                                                                                         \
        if (!(cond)) {                                                                           \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__ << " " << #cond << '\n';         \
            std::exit(1);                                                                        \
        }                                                                                        \
    } while (0)
