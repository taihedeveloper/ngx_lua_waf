--[[
-------------------------------------------------------------------------------------------
    @Author: luohongcang@taihe.com
    @Comment: 基于https://github.com/loveshell/ngx_lua_waf
              对ODP中的waf行为进行了修改和补充
-------------------------------------------------------------------------------------------
]]
local conf = require "wafconfig"
local M = {}

-- 获取conf文件中的配置值
local log_path = conf.logdir 
local rule_path = conf.RulePath
local url_deny = conf.UrlDeny
local post_check = conf.postMatch
local cookie_check = conf.CookieMatch
local white_check = conf.whiteModule
local attacklog = conf.attacklog
local CCDeny = conf.CCDeny
local CCrate = conf.CCrate
local ipCCrate = conf.ipCCrate
local ipWhitelist = conf.ipWhitelist
local ipBlocklist = conf.ipBlocklist
local black_fileExt = conf.black_fileExt

--[[
    @comment 判断开关是否开启
    @param
    @return
]]
local function optionIsOn(options)
    if options == "on" then
        return true
    else
        return false
    end
end

--[[
    @comment 获取客户端IP
    @param
    @return
]]
local function getClientIp()
    local IP = ngx.var.remote_addr 
    if IP == nil then
        IP = "unknown"
    end

    return IP
end

--[[
    @comment 写文件操作
    @param
    @return
]]
local function write(logfile, msg)
    local fd = io.open(logfile, "ab")
    if fd == nil then 
        return
    end
    fd:write(msg)
    fd:flush()
    fd:close()
end

--[[
    @comment 写日志操作
    @param
    @return
]]
local function wafLog(data, ruletag)
    local request_method = ngx.req.get_method()
    local url = ngx.var.request_uri
    if optionIsOn(attacklog) then
        local realIp = getClientIp()
        local ua = ngx.var.http_user_agent
        local servername = ngx.var.server_name
        local time = ngx.localtime()
        if ua then
            line = realIp .. " [" .. time .. "] \"" .. request_method .. " " .. servername .. url .. "\" \"" .. data .. "\"  \"" .. ua .. "\" \"" .. ruletag .. "\"\n"
        else
            line = realIp .. " [" .. time .. "] \"" .. request_method .. " " .. servername .. url .. "\" \"" .. data .. "\" - \"" .. ruletag .. "\"\n"
        end
 
        local filename = log_path .. "/waf.log"
        write(filename, line)
    end
end

--[[
    @comment 获取过滤规则
    @param
    @return
]]
local function readRule(var)
    local file = io.open(rule_path .. "/" .. var, "r")
    if file == nil then
        return
    end
    local ret = {}
    for line in file:lines() do
        table.insert(ret, line)
    end
    file:close()

    return ret
end

--[[
    @comment 返回403页面
    @param
    @return
]]
local function sayHtml()
    ngx.header.content_type = "text/html"
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.exit(ngx.status)
end

--[[
    @comment 获取是否检测post参数值
    @param
    @return
]]
local function getPostCheckFlag()
    return optionIsOn(post_check)
end

--[[
    @comment 白名单url匹配
    @param
    @return
]]
local function whiteUrl()
    if optionIsOn(white_check) then
        g_white_url_rules = g_white_url_rules or readRule("whiteurl")
        if g_white_url_rules and type(g_white_url_rules) == 'table' then
            for _, rule in pairs(g_white_url_rules) do
                if ngx.re.match(ngx.var.uri, rule, "isjo") then
                    return true 
                end
            end
        end
    end

    return false
end

--[[
    @comment 文件后缀匹配
    @param
    @return
]]
local function fileExtCheck(ext)
    local items = {}
    for _, val in pairs(black_fileExt) do
        items[val] = true
    end

    ext = string.lower(ext)
    if ext then
        for rule in pairs(items) do
            if ngx.re.match(ext, rule, "isjo") then
                wafLog("-", "file attack with ext. file: " .. ext .. " rule: " .. rule)
                sayHtml()
            end
        end
    end

    return false
end

--[[
    @comment 参数匹配
    @param
    @return
]]
local function args()
    g_args_rules = g_args_rules or readRule("args")
    if g_args_rules and type(g_args_rules) == 'table' then
        for _, rule in pairs(g_args_rules) do
            local data
            local args = ngx.req.get_uri_args()
            for key, val in pairs(args) do
                if type(val) == "table" then
                     local t = {}
                     for k, v in pairs(val) do
                        if v == true then
                            v = ""
                        end
                        table.insert(t, v)
                    end
                    data = table.concat(t, " ")
                else
                    data = val
                end
                if data and type(data) ~= "boolean" and rule ~= "" and ngx.re.match(ngx.unescape_uri(data), rule, "isjo") then
                    wafLog("-", "args in attack rules: " .. rule .. " data: " .. tostring(data))
                    sayHtml()
                    return true
                end
            end
        end
    end

    return false
end

--[[
    @comment url规则匹配
    @param
    @return
]]
local function url()
    if optionIsOn(url_deny) then
        g_url_rules = g_url_rules or readRule("url")
        if g_url_rules and type(g_url_rules) == 'table' then
            for _, rule in pairs(g_url_rules) do
                if rule ~= "" and ngx.re.match(ngx.var.request_uri, rule, "isjo") then
                    wafLog("-", "url in attack rules: " .. rule)
                    sayHtml()
                    return true
                end
            end
        end
    end

    return false
end

--[[
    @comment ua规则匹配
    @param
    @return
]]
local function ua()
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
        g_ua_rules = g_ua_rules or readRule("user-agent")
        if g_ua_rules and type(g_ua_rules) == 'table' then
            for _, rule in pairs(g_ua_rules) do
                if rule ~= "" and ngx.re.match(ua, rule, "isjo") then
                    wafLog("-", "ua in attack rules: " .. rule)
                    sayHtml()
                    return true
                end
            end
        end
    end

    return false
end

--[[
    @comment 过滤body中的数据
    @param
    @return
]]
local function body(data)
    g_post_rules = g_post_rules or readRule("post")
    if g_post_rules and type(g_post_rules) == 'table' then
        for _, rule in pairs(g_post_rules) do
            if rule ~= "" and data ~= "" and ngx.re.match(ngx.unescape_uri(data), rule, "isjo") then
                wafLog(data, rule)
                sayHtml()
                return true
            end
        end
    end

    return false
end

--[[
    @comment cookie规则匹配
    @param
    @return
]]
local function cookie()
    local cookie_check_flag = optionIsOn(cookie_check)
    local now_cookie = ngx.var.http_cookie
    if cookie_check_flag and now_cookie then
        g_cookie_rules = g_cookie_rules or readRule("cookie")
        if g_cookie_rules and type(g_cookie_rules) == 'table' then
            for _, rule in pairs(g_cookie_rules) do
                if rule ~= "" and ngx.re.match(now_cookie, rule, "isjo") then
                    wafLog("-", "cookie in attack rules: " .. rule)
                    sayHtml()
                    return true
                end
            end
        end
    end

    return false
end

--[[
    @comment cc攻击匹配
    @param
    @return
]]
local function denyCC()
    if optionIsOn(CCDeny) then
        local uri = ngx.var.uri
        local CCcount = tonumber(string.match(CCrate, "(.*)/"))
        local CCseconds = tonumber(string.match(CCrate, "/(.*)"))
        local ipCCcount = tonumber(string.match(ipCCrate, "(.*)/"))
        local ipCCseconds = tonumber(string.match(ipCCrate, "/(.*)"))
        local now_ip = getClientIp()

        local token = now_ip .. uri
        local limit = ngx.shared.limit
        local iplimit = ngx.shared.iplimit
        local req, _ = limit:get(token)
        local ipreq, _ = iplimit:get(now_ip)

        if req then -- ip访问url频次检测
            if req > CCcount then
                wafLog("-", "ip get url over times. ")
                sayHtml()
                return true
            else
                limit:incr(token, 1)
            end
        else
            limit:set(token, 1, CCseconds)
        end

        if ipreq then -- 访问ip频次检测
            if ipreq > ipCCcount then
                wafLog("-", "ip get host over times. ")
                sayHtml()
                return true
            else
                iplimit:incr(now_ip, 1)
            end
        else
            iplimit:set(now_ip, 1, ipCCseconds)
        end
    end

    return false
end

--[[
    @comment 获取content-type中的boundary
    @param
    @return
]]
local function getBoundary()
    local header = ngx.req.get_headers()["content-type"]
    if not header then
        return nil
    end

    if type(header) == "table" then
        header = header[1]
    end

    local m = string.match(header, ";%s*boundary=\"([^\"]+)\"")
    if m then
        return m
    end

    return string.match(header, ";%s*boundary=([^\",;]+)")
end

--[[
    @comment 字符串分割函数，用作ip的模式匹配用
    @param
    @return
]]
local function split(str, split_char)
    if str == "" then
        return {}
    end
    local sub_str_tab = {};
    while (true) do
        local pos = string.find(str, split_char, 1, true);
        if (not pos) then
            sub_str_tab[#sub_str_tab + 1] = str;
            break;
        end
        local sub_str = string.sub(str, 1, pos - 1);
        sub_str_tab[#sub_str_tab + 1] = sub_str;
        str = string.sub(str, pos + string.len(split_char), #str);
    end

    return sub_str_tab;
end

--[[
    @comment 白名单ip过滤
    @param
    @return
]]
local function whiteip()
    if ipWhitelist and type(ipWhitelist) == 'table' then
        for _, val in pairs(ipWhitelist) do
            local now_ip = getClientIp()
            local now_ip_arr = split(now_ip, ".")
            local rule_arr = split(val, ".")
            local flag = 0
            if #now_ip_arr == #rule_arr then
                for i = 1, #rule_arr do
                    if rule_arr[i] == "*" or now_ip_arr[i] == rule_arr[i] then
                        flag = flag + 1
                    end
                end
            end
            if flag == #rule_arr then
                return true
            end
        end
    end

    return false
end

--[[
    @comment 黑名单ip过滤
    @param
    @return
]]
local function blockip()
    if ipBlocklist and type(ipBlocklist) == 'table' then
        for _, val in pairs(ipBlocklist) do
            local now_ip = getClientIp()
            local now_ip_arr = split(now_ip, ".")
            local rule_arr = split(val, ".")
            local flag = 0
            if #now_ip_arr == #rule_arr then
                for i = 1, #rule_arr do
                    if rule_arr[i] == "*" or now_ip_arr[i] == rule_arr[i] then
                        flag = flag + 1
                    end
                end
            end
            if flag == #rule_arr then
                wafLog("-", "ip in black lists. ")
                sayHtml()
                return true
            end
        end
    end

    return false
end

M.getPostCheckFlag = getPostCheckFlag
M.whiteUrl = whiteUrl
M.fileExtCheck = fileExtCheck
M.args = args
M.url = url
M.ua = ua
M.body = body
M.cookie = cookie
M.denyCC = denyCC
M.getBoundary = getBoundary
M.whiteip = whiteip
M.blockip = blockip

return M
