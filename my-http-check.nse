
description = [[
Checks whether an HTTP service is running on port 80.
]]

author = "Maria Hashmi"

license = "Same as Nmap"

categories = {"safe", "discovery"}

local shortport = require "shortport"

portrule = shortport.port_or_service(80, "http")

action = function(host, port)
    return "HTTP service detected on port " .. port.number
end
