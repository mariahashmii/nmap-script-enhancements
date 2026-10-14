
description = [[
Connects to an SSH service and attempts to retrieve its
identification banner, which may reveal the SSH version
and server implementation.
]]

author = "Maria Hashmi"

license = "Same as Nmap"

categories = {"safe", "discovery"}

local shortport = require "shortport"
local nmap = require "nmap"

portrule = shortport.ssh

action = function(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status = socket:connect(host, port)

    if not status then
        socket:close()
        return "Unable to connect to SSH service."
    end

    local received, banner = socket:receive_buf("\r?\n", false)
    socket:close()

    if not received or not banner then
        return "SSH banner not received."
    end

    banner = banner:gsub("[\r\n]+$", "")

    if banner:match("^SSH%-") then
        return "SSH Banner: " .. banner
    end

    return "Received data, but no SSH identification banner was found."
end
