
description = [[
Checks whether a DNS service is running on port 53.
]]

author = "Maria Hashmi"

license = "Same as Nmap"

categories = {"safe", "discovery"}

local shortport = require "shortport"

portrule = shortport.port_or_service(53, "domain")

action = function(host, port)
    return "DNS service is running on port " .. port.number
end
