
description = [[
Retrieves the HTTP Server header from a web server.
This helps identify the web server software (Apache, nginx, etc.).
]]

author = "Maria Hashmi"

license = "Same as Nmap"

categories = {"safe", "discovery"}

local shortport = require "shortport"
local http = require "http"

portrule = shortport.http

action = function(host, port)
    local response = http.get(host, port, "/")

    if not response then
        return "No HTTP response received."
    end

    if response.header and response.header.server then
        return "HTTP Server: " .. response.header.server
    end

    return "Server header not found."
end
