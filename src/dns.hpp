#pragma once

#include "state.hpp"

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>

namespace wirebone {

class MagicDns {
public:
    MagicDns(Store& store, std::string domain, std::string listen);
    ~MagicDns();

    void start();
    void stop();
    std::string bound_address() const { return bound_; }

private:
    void loop();
    bool answer(const std::uint8_t* q, int qlen, std::vector<std::uint8_t>& resp);

    Store& store_;
    std::string domain_;
    std::string listen_;
    std::string bound_;
    int fd_ = -1;
    std::atomic<bool> stop_{false};
    std::thread thread_;
};

}  // namespace wirebone
