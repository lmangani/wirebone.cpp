#pragma once

#include "noise.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace wirebone {

class H2Server {
public:
    using RequestHandler = std::function<void(int32_t stream_id, const std::string& method,
                                              const std::string& path, const std::string& body)>;
    using ExtraHandler = std::function<void()>;

    explicit H2Server(NoiseConn& conn);
    ~H2Server();

    H2Server(const H2Server&) = delete;
    H2Server& operator=(const H2Server&) = delete;

    void reply(int32_t stream_id, int status, std::string_view content_type,
               std::vector<std::uint8_t> body);
    void reply_stream_start(int32_t stream_id, int status,
                            std::vector<std::uint8_t> first_frame = {});
    void push_data(int32_t stream_id, std::vector<std::uint8_t> data);
    void end_stream(int32_t stream_id);

    // Blocks until the Noise connection closes. extra_fd, if >= 0, is polled
    // and on_extra is invoked when it becomes readable. on_tick runs every
    // loop iteration (about once a second) for keepalives and map fan-out.
    void run(RequestHandler on_request, int extra_fd = -1, ExtraHandler on_extra = {},
             ExtraHandler on_tick = {});

    bool alive() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace wirebone
