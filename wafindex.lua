--[[
-------------------------------------------------------------------------------------------
    @Author: luohongcang@taihe.com
    @Comment: 基于https://github.com/loveshell/ngx_lua_waf
              对ODP中的waf行为进行了修改和补充
-------------------------------------------------------------------------------------------
]]
local m_init = require "wafinit"

if m_init.whiteip() then
    return
end

if m_init.blockip() then
    return
end

if m_init.denyCC() then
    return
end

if ngx.var.http_Acunetix_Aspect then
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

if ngx.var.http_X_Scan_Memo then
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

if m_init.whiteUrl() then
    return
end

if m_init.ua() then
    return
end

if m_init.url() then
    return
end

if m_init.args() then
    return
end

if m_init.cookie() then
    return
end

if m_init.getPostCheckFlag() then
    if ngx.req.get_method() == "POST" then
        local boundary = m_init.getBoundary()
        if boundary then
            local len = string.len
            local sock, err = ngx.req.socket()
            if not sock then
                return
            end
            ngx.req.init_body(128 * 1024)
            sock:settimeout(0)
            local content_length = tonumber(ngx.req.get_headers()["content-length"])
            local chunk_size = 4096
            if content_length < chunk_size then
                chunk_size = content_length
            end
            local size = 0
            while size < content_length do
                local filetranslate = true
                local data, err, partial = sock:receive(chunk_size)
                data = data or partial
                if not data then
                    return
                end
                ngx.req.append_body(data)
                if m_init.body(data) then
                    return true
                end
                size = size + len(data)
                local m = ngx.re.match(data, 'Content-Disposition: form-data;(.+)filename="(.+)\\.(.*)"', "ijo")
                if m then
                    m_init.fileExtCheck(m[3]) -- 检测文件名是否后缀命中规则
                    filetranslate = true
                else
                    if ngx.re.match(data, "Content-Disposition:", "isjo") then
                        filetranslate = false
                    end
                    if filetranslate == false then
                        if m_init.body(data) then
                            return true
                        end
                    end
                end
                local less = content_length - size
                if less < chunk_size then
                    chunk_size = less
                end
            end
            ngx.req.finish_body()
        else
            ngx.req.read_body()
            local args = ngx.req.get_post_args()
            if not args then
                return
            end
            for key, val in pairs(args) do
                local data
                if type(val) == "table" then
                    if type(val[1]) == "boolean" then
                        return
                    end
                    data = table.concat(val, ", ")
                else
                    data = val
                end
                if data and type(data) ~= "boolean" and not m_init.body(data) then
                    m_init.body(key)
                end
            end
        end
    end
else
    return
end
