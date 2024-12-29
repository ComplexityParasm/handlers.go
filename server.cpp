#include <iostream>
#include <httplib.h>
#include <string>
#include <json.hpp>
// ... JWT library etc

bool validateToken(const std::string& token) {
  // Реализация проверки JWT
    return true; //TODO: return true on valid, false otherwise
}

bool checkPermissions(const std::string& token, const std::string& requiredPermission) {
    // Реализация проверки прав доступа
    return true; //TODO: return true on valid, false otherwise
}

int main() {
  httplib::Server svr;
  svr.Get("/", [](const httplib::Request& req, httplib::Response& res) {
        res.set_content("Hello from C++", "text/plain");
    });
    svr.Get("/protected", [](const httplib::Request& req, httplib::Response& res) {
      // Get cookie from req
      // if no cookie, return 401
      std::string token; // TODO: get token from cookie
      if (!validateToken(token)) {
        res.status = 401;
        return;
      }

       if (!checkPermissions(token, "view_self_info")) {
            res.status = 403;
            return;
        }
       // ...
       res.set_content("Protected page", "text/plain")
    });
    svr.listen("0.0.0.0", 8080);
    return 0;
}
