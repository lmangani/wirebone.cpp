#include "http2_session.hpp"

#include <nghttp2/nghttp2.h>
#include <poll.h>

#include <cstring>
#include <map>
#include <stdexcept>
#include <vector>

namespace wirebone {
namespace {

struct Stream {
    int32_t id = 0;
    std::string method;
    std::string path;
    std::string body;
    std::vector<std::uint8_t> out;
    std::size_t out_off = 0;
    bool streaming = false;
    bool ended = false;
};

nghttp2_nv nv(const char* name, const char* value) {
    return nghttp2_nv{reinterpret_cast<uint8_t*>(const_cast<char*>(name)),
                      reinterpret_cast<uint8_t*>(const_cast<char*>(value)), strlen(name),
                      strlen(value), NGHTTP2_NV_FLAG_NONE};
}

}  // namespace

class H2Server::Impl {
public:
    explicit Impl(NoiseConn& conn) : conn_(conn) {
        nghttp2_session_callbacks* cbs = nullptr;
        nghttp2_session_callbacks_new(&cbs);
        nghttp2_session_callbacks_set_send_callback(cbs, send_cb);
        nghttp2_session_callbacks_set_on_begin_headers_callback(cbs, on_begin_headers);
        nghttp2_session_callbacks_set_on_header_callback(cbs, on_header);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, on_data);
        nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, on_frame);
        nghttp2_session_callbacks_set_on_stream_close_callback(cbs, on_close);
        nghttp2_session_server_new(&session_, cbs, this);
        nghttp2_session_callbacks_del(cbs);

        nghttp2_settings_entry iv{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100};
        nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, &iv, 1);
        nghttp2_session_send(session_);
    }

    ~Impl() {
        if (session_) {
            nghttp2_session_del(session_);
        }
    }

    static ssize_t send_cb(nghttp2_session*, const uint8_t* data, size_t length, int, void* user) {
        auto* self = static_cast<Impl*>(user);
        const int n = self->conn_.write(data, static_cast<int>(length));
        if (n < 0) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        if (n == 0) {
            return NGHTTP2_ERR_WOULDBLOCK;
        }
        return n;
    }

    static int on_begin_headers(nghttp2_session* session, const nghttp2_frame* frame, void* user) {
        if (frame->hd.type != NGHTTP2_HEADERS ||
            frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
            return 0;
        }
        auto* self = static_cast<Impl*>(user);
        auto st = std::make_unique<Stream>();
        st->id = frame->hd.stream_id;
        nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, st.get());
        self->streams_[frame->hd.stream_id] = std::move(st);
        return 0;
    }

    static int on_header(nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name,
                         size_t namelen, const uint8_t* value, size_t valuelen, uint8_t, void*) {
        if (frame->hd.type != NGHTTP2_HEADERS) {
            return 0;
        }
        auto* st = static_cast<Stream*>(nghttp2_session_get_stream_user_data(session, frame->hd.stream_id));
        if (!st) {
            return 0;
        }
        const std::string n(reinterpret_cast<const char*>(name), namelen);
        const std::string v(reinterpret_cast<const char*>(value), valuelen);
        if (n == ":method") {
            st->method = v;
        } else if (n == ":path") {
            st->path = v;
        }
        return 0;
    }

    static int on_data(nghttp2_session* session, uint8_t, int32_t stream_id, const uint8_t* data,
                       size_t len, void*) {
        auto* st = static_cast<Stream*>(nghttp2_session_get_stream_user_data(session, stream_id));
        if (st) {
            st->body.append(reinterpret_cast<const char*>(data), len);
        }
        return 0;
    }

    static int on_frame(nghttp2_session* session, const nghttp2_frame* frame, void* user) {
        if ((frame->hd.type != NGHTTP2_HEADERS && frame->hd.type != NGHTTP2_DATA) ||
            (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) == 0) {
            return 0;
        }
        auto* self = static_cast<Impl*>(user);
        auto* st = static_cast<Stream*>(nghttp2_session_get_stream_user_data(session, frame->hd.stream_id));
        if (!st || !self->on_request_) {
            return 0;
        }
        self->on_request_(st->id, st->method, st->path, st->body);
        return 0;
    }

    static int on_close(nghttp2_session*, int32_t stream_id, uint32_t, void* user) {
        auto* self = static_cast<Impl*>(user);
        self->streams_.erase(stream_id);
        return 0;
    }

    static ssize_t data_read(nghttp2_session*, int32_t stream_id, uint8_t* buf, size_t length,
                             uint32_t* data_flags, nghttp2_data_source* source, void*) {
        auto* st = static_cast<Stream*>(source->ptr);
        (void)stream_id;
        if (st->out_off >= st->out.size()) {
            if (st->ended && !st->streaming) {
                *data_flags |= NGHTTP2_DATA_FLAG_EOF;
                return 0;
            }
            if (st->streaming && !st->ended) {
                return NGHTTP2_ERR_DEFERRED;
            }
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            return 0;
        }
        const std::size_t n = std::min(length, st->out.size() - st->out_off);
        std::memcpy(buf, st->out.data() + st->out_off, n);
        st->out_off += n;
        if (st->out_off >= st->out.size()) {
            st->out.clear();
            st->out_off = 0;
            if (!st->streaming || st->ended) {
                *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            }
        }
        return static_cast<ssize_t>(n);
    }

    void submit_response(int32_t stream_id, int status, const char* ctype, bool streaming) {
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        Stream* st = it->second.get();
        st->streaming = streaming;
        status_buf_[stream_id] = std::to_string(status);
        ctype_buf_[stream_id] = ctype ? ctype : "application/json";

        nghttp2_data_provider prd{};
        prd.source.ptr = st;
        prd.read_callback = data_read;
        const std::string& status_s = status_buf_[stream_id];
        const std::string& ctype_s = ctype_buf_[stream_id];
        nghttp2_nv hdrs[] = {
            nv(":status", status_s.c_str()),
            nv("content-type", ctype_s.c_str()),
        };
        nghttp2_submit_response(session_, stream_id, hdrs, 2, &prd);
        // Do not session_send here — we are often inside on_frame_recv.
    }

    void reply(int32_t stream_id, int status, std::string_view content_type,
               std::vector<std::uint8_t> body) {
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        it->second->out = std::move(body);
        it->second->out_off = 0;
        it->second->ended = true;
        it->second->streaming = false;
        const std::string ctype(content_type);
        submit_response(stream_id, status, ctype.c_str(), false);
    }

    void reply_stream_start(int32_t stream_id, int status, std::vector<std::uint8_t> first) {
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        it->second->out = std::move(first);
        it->second->out_off = 0;
        it->second->streaming = true;
        it->second->ended = false;
        submit_response(stream_id, status, "application/json", true);
    }

    void push_data(int32_t stream_id, std::vector<std::uint8_t> data) {
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        auto& st = *it->second;
        st.out.insert(st.out.end(), data.begin(), data.end());
        nghttp2_session_resume_data(session_, stream_id);
    }

    void end_stream(int32_t stream_id) {
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        it->second->ended = true;
        it->second->streaming = false;
        nghttp2_session_resume_data(session_, stream_id);
    }

    void run(RequestHandler on_request, int extra_fd, ExtraHandler on_extra, ExtraHandler on_tick) {
        on_request_ = std::move(on_request);
        std::uint8_t buf[8192];
        while (true) {
            pollfd fds[2]{};
            fds[0].fd = conn_.fd();
            fds[0].events = POLLIN;
            nfds_t nfds = 1;
            if (extra_fd >= 0) {
                fds[1].fd = extra_fd;
                fds[1].events = POLLIN;
                nfds = 2;
            }
            const int pr = ::poll(fds, nfds, 1000);
            if (pr < 0) {
                break;
            }
            if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                break;
            }
            if (fds[0].revents & POLLIN) {
                const int n = conn_.read(buf, sizeof(buf));
                if (n <= 0) {
                    break;
                }
                const ssize_t rv = nghttp2_session_mem_recv(session_, buf, static_cast<size_t>(n));
                if (rv < 0) {
                    break;
                }
            }
            if (nghttp2_session_want_write(session_)) {
                if (nghttp2_session_send(session_) != 0) {
                    break;
                }
            }
            if (nfds == 2 && (fds[1].revents & POLLIN) && on_extra) {
                on_extra();
            }
            if (on_tick) {
                on_tick();
            }
            if (nghttp2_session_want_write(session_)) {
                if (nghttp2_session_send(session_) != 0) {
                    break;
                }
            }
            if (nghttp2_session_want_read(session_) == 0 && nghttp2_session_want_write(session_) == 0) {
                break;
            }
        }
        alive_ = false;
    }

    bool alive() const { return alive_; }

    NoiseConn& conn_;
    nghttp2_session* session_ = nullptr;
    std::map<int32_t, std::unique_ptr<Stream>> streams_;
    std::map<int32_t, std::string> status_buf_;
    std::map<int32_t, std::string> ctype_buf_;
    RequestHandler on_request_;
    bool alive_ = true;
};

H2Server::H2Server(NoiseConn& conn) : impl_(std::make_unique<Impl>(conn)) {}
H2Server::~H2Server() = default;

void H2Server::reply(int32_t stream_id, int status, std::string_view content_type,
                     std::vector<std::uint8_t> body) {
    impl_->reply(stream_id, status, content_type, std::move(body));
}

void H2Server::reply_stream_start(int32_t stream_id, int status,
                                  std::vector<std::uint8_t> first_frame) {
    impl_->reply_stream_start(stream_id, status, std::move(first_frame));
}

void H2Server::push_data(int32_t stream_id, std::vector<std::uint8_t> data) {
    impl_->push_data(stream_id, std::move(data));
}

void H2Server::end_stream(int32_t stream_id) { impl_->end_stream(stream_id); }

void H2Server::run(RequestHandler on_request, int extra_fd, ExtraHandler on_extra,
                   ExtraHandler on_tick) {
    impl_->run(std::move(on_request), extra_fd, std::move(on_extra), std::move(on_tick));
}

bool H2Server::alive() const { return impl_ && impl_->alive(); }

}  // namespace wirebone
