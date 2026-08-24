#include "http1.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <sstream>

namespace wirebone {
namespace {

std::string lower(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

}  // namespace

bool write_all(int fd, std::string_view data) {
    std::size_t off = 0;
    while (off < data.size()) {
        const ssize_t n = ::send(fd, data.data() + off, data.size() - off, 0);
        if (n <= 0) {
            return false;
        }
        off += static_cast<std::size_t>(n);
    }
    return true;
}

void write_http_response(int fd, int status, std::string_view status_text,
                         std::string_view content_type, std::string_view body) {
    std::ostringstream os;
    os << "HTTP/1.1 " << status << ' ' << status_text << "\r\n"
       << "Content-Type: " << content_type << "\r\n"
       << "Content-Length: " << body.size() << "\r\n"
       << "Connection: close\r\n\r\n"
       << body;
    write_all(fd, os.str());
}

std::string header_get(const HttpRequest& req, std::string_view name) {
    const std::string key = lower(std::string(name));
    const auto it = req.headers.find(key);
    return it == req.headers.end() ? std::string() : it->second;
}

std::string query_get(std::string_view query, std::string_view key) {
    std::size_t start = 0;
    while (start < query.size()) {
        const auto amp = query.find('&', start);
        const auto part = query.substr(start, amp == std::string_view::npos ? query.size() - start
                                                                           : amp - start);
        const auto eq = part.find('=');
        const auto k = part.substr(0, eq);
        if (k == key) {
            return std::string(eq == std::string_view::npos ? "" : part.substr(eq + 1));
        }
        if (amp == std::string_view::npos) {
            break;
        }
        start = amp + 1;
    }
    return {};
}

bool read_http_request(int fd, HttpRequest& req, std::string& extra) {
    std::string buf;
    buf.reserve(4096);
    char tmp[1024];
    while (buf.find("\r\n\r\n") == std::string::npos) {
        const ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
        if (n <= 0) {
            return false;
        }
        buf.append(tmp, static_cast<std::size_t>(n));
        if (buf.size() > 64 * 1024) {
            return false;
        }
    }
    const auto hdr_end = buf.find("\r\n\r\n");
    extra = buf.substr(hdr_end + 4);
    std::istringstream in(buf.substr(0, hdr_end));
    std::string line;
    if (!std::getline(in, line)) {
        return false;
    }
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }
    std::istringstream first(line);
    first >> req.method >> req.target;
    const auto q = req.target.find('?');
    if (q == std::string::npos) {
        req.path = req.target;
    } else {
        req.path = req.target.substr(0, q);
        req.query = req.target.substr(q + 1);
    }
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        const auto colon = line.find(':');
        if (colon == std::string::npos) {
            continue;
        }
        std::string name = lower(line.substr(0, colon));
        std::string value = line.substr(colon + 1);
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
            value.erase(value.begin());
        }
        req.headers[std::move(name)] = std::move(value);
    }
    return true;
}

}  // namespace wirebone
