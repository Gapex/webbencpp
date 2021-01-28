#include <iostream>
#include <cstdlib>
#include <string>
#include <tuple>
#include <regex>
#include <unordered_map>
#include <atomic>
#include <thread>

static const std::string DEFUALT_URL = "http://www.baidu.com/";

std::tuple<std::string, std::string, std::string>
url_split(const std::string &url)
{
    std::regex pattern("^(.*)://([a-zA-Z-.]{1,})(/.*)$");
    std::smatch groups;
    bool is_match = std::regex_match(url, groups, pattern);
    if (is_match == false)
    {
        return std::make_tuple("", "", "");
    }
    return std::make_tuple(
        groups[1],
        groups[2],
        groups[3]);
}

enum class HTTPMethod
{
    GET,
    HEAD,
    OPTIONS,
    TRACE
};

class HTTPRequestLine
{
private:
    HTTPMethod method;
    std::string path;
    std::string http_version;

public:
    HTTPRequestLine(HTTPMethod m = HTTPMethod::GET, const std::string &path = "/", const std::string http_version = "1.1") : method(m), path(path)
    {
        this->http_version += "HTTP/";
        this->http_version += http_version;
    }

    std::string to_string() const
    {
        static std::unordered_map<HTTPMethod, const std::string> method_map = {
            {HTTPMethod::GET, "GET"},
            {HTTPMethod::HEAD, "HEAD"},
            {HTTPMethod::OPTIONS, "OPTIONS"},
            {HTTPMethod::TRACE, "TRACE"}};
        std::string method_str = method_map[method];
        std::ostringstream os;
        os << method_str << ' ' << path << ' ' << http_version << "\r\n";
        return os.str();
    }

    HTTPMethod get_method() const
    {
        return method;
    }

    HTTPMethod set_method(HTTPMethod m)
    {
        HTTPMethod old = method;
        method = m;
        return old;
    }

    const std::string &get_path() const
    {
        return path;
    }

    std::string set_path(const std::string &new_path)
    {
        std::string old_path = path;
        path = new_path;
        return std::move(old_path);
    }
};

class HTTPHeader
{
private:
    std::string header_name;
    std::string header_value;

public:
    HTTPHeader(const std::string &name = "", const std::string &value = "") : header_name(name), header_value(value)
    {
    }

    std::string to_string() const
    {
        if (header_name.empty())
        {
            return "";
        }
        std::ostringstream os;
        os << header_name << ": " << header_value << "\r\n";
        return os.str();
    }
};

class HTTPRequest
{
private:
    HTTPRequestLine request_line;
    std::vector<HTTPHeader> headers;

public:
    HTTPRequest(const HTTPRequestLine &request_line,
                const std::vector<HTTPHeader> &headers) : request_line(request_line),
                                                          headers(headers.begin(), headers.end())
    {
    }

    HTTPRequest() {}

    void set_method(HTTPMethod m)
    {
        request_line.set_method(m);
    }

    std::string to_string() const
    {
        std::string res;
        res += request_line.to_string();
        for (auto &header : headers)
        {
            res += header.to_string();
        }
        res += "\r\n";
        return std::move(res);
    }

    explicit operator const std::string() const
    {
        return this->to_string();
    }

    void append_header(const HTTPHeader &header)
    {
        headers.push_back(header);
    }

    void append_header(const std::string &name, const std::string &value)
    {
        headers.emplace_back(name, value);
    }

    const HTTPRequestLine &get_request_line() const
    {
        return request_line;
    }

    friend std::ostream &operator<<(std::ostream &os, const HTTPRequest &request);
};

std::ostream &operator<<(std::ostream &os, const HTTPRequest &request)
{
    return os << request.to_string();
}

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

class TCPSocket
{
private:
    int port;
    int sockfd;
    const std::string addr_str;
    struct sockaddr_in addr_info;

public:
    TCPSocket(const std::string &addr, const int port) : addr_str(addr), port(port)
    {
        memset(&addr_info, 0, sizeof(addr_info));
        addr_info.sin_family = AF_INET;
        auto inaddr = inet_addr(addr_str.c_str());
        if (inaddr != INADDR_NONE)
        {
            memcpy(&(addr_info.sin_addr), &inaddr, sizeof(inaddr));
        }
        else
        {
            struct hostent *hostent_ptr = gethostbyname(addr_str.c_str());
            if (hostent_ptr != NULL)
            {
                memcpy(&(addr_info.sin_addr), hostent_ptr->h_addr, hostent_ptr->h_length);
            }
            else
            {
                std::cerr << __LINE__ << ' ' << __FILE__ << ' ' << "gethostbyname()" << std::endl;
            }
        }
        addr_info.sin_port = htons(port);
        sockfd = socket(AF_INET, SOCK_STREAM, 0); //TCP socket
        if (sockfd < 0)
        {
            std::cerr << __LINE__ << ' ' << __FILE__ << ' ' << "socket(), sockefd < 0 " << std::endl;
        }
    }

    int connect() const
    {
        int status = ::connect(sockfd, (struct sockaddr *)&addr_info, sizeof(addr_info));
        return status;
    }

    int get_fd() const
    {
        return sockfd;
    }

    ~TCPSocket()
    {
        close(sockfd);
    }

    int write(const std::string &msg)
    {
        size_t nbytes = msg.size();
        size_t nwritten = 0;
        while ((nwritten = ::write(sockfd, msg.c_str() + nwritten, nbytes - nwritten)) != nbytes)
        {
        }
        return nwritten;
    }

    std::string read(int nbytes)
    {
        if (nbytes == -1)
        {
            nbytes = std::numeric_limits<int>().max();
        }
        std::string res;
        char buf[4096];
        size_t nread = 0;
        while ((nread = ::read(sockfd, buf, sizeof(buf))) > 0 && res.size() < nbytes)
        {
            buf[nread] = '\0';
            res += buf;
        }
        if (nread < 0)
        {
            res += "<! error !>";
        }
        return res;
    }
};

int main(int argc, char *argv[])
{
    std::string target_url;
    if (argc < 2)
    {
        target_url = DEFUALT_URL;
    }
    else
    {
        target_url = std::string(argv[1]);
    }
    const int nthread = 20;
    std::string protocol, host, path;
    std::tie(protocol, host, path) = url_split(target_url);
    HTTPRequest req;
    req.set_method(HTTPMethod::GET);
    req.append_header("User-Agent", "Webench++ 0.0.1");
    req.append_header("Host", host);
    req.append_header("Connection", "close");
    std::cout << req << std::endl;
    std::atomic<int> total_cnt, success_cnt, failure_cnt;
    total_cnt.store(0, std::memory_order::memory_order_seq_cst);
    success_cnt.store(0, std::memory_order::memory_order_seq_cst);
    failure_cnt.store(0, std::memory_order::memory_order_seq_cst);

    auto test = [&req, &host, &total_cnt, &success_cnt, &failure_cnt]() {
        TCPSocket ts(host, 80);
        total_cnt += 1;
        if (ts.connect() == 0)
        {
            if (ts.write(req.to_string()))
            {
                ts.read(-1);
                success_cnt += 1;
            }
            else
            {
                failure_cnt += 1;
            }
        }
        else
        {
            failure_cnt += 1;
        }
    };
    std::vector<std::thread> ts;
    ts.reserve(nthread);
    for (int i = 0; i < nthread; ++i)
    {
        std::thread t(test);
        ts.emplace_back(std::move(t));
    }
    for (auto &t : ts)
    {
        t.join();
    }
    int total = total_cnt.load(), succ = success_cnt.load(), failed = failure_cnt.load();
    ::printf("SUMMERY:\n");
    ::printf("\tTotal %d\tSuccess: %d\tFailed: %d\n", total, succ, failed);
    return 0;
}