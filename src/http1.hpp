#pragma once

#include <map>
#include <string>
#include <string_view>

namespace wirebone {

struct HttpRequest {
    std::string method;
    std::string target;
    std::string path;
    std::string query;
    std::map<std::string, std::string> headers;
};

bool read_http_request(int fd, HttpRequest& req, std::string& extra);
bool write_all(int fd, std::string_view data);
void write_http_response(int fd, int status, std::string_view status_text,
                         std::string_view content_type, std::string_view body);
std::string header_get(const HttpRequest& req, std::string_view name);
std::string query_get(std::string_view query, std::string_view key);

}  // namespace wirebone
