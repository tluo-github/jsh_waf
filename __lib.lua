--
-- Created by IntelliJ IDEA.
-- Author: Bruce
-- Date: 2016/10/21
-- waf 核心模块
--
require '__config'

--[[
-- 获得客户端IP
 ]]
function get_client_ip()
    CLIENT_IP = ngx.req.get_headers()["X_real_ip"]
    if CLIENT_IP == nil then
        CLIENT_IP = ngx.req.get_headers()["X_Forwarded_For"]
    end
    if CLIENT_IP == nil then
        CLIENT_IP  = ngx.var.remote_addr
    end
    if CLIENT_IP == nil then
        CLIENT_IP  = "unknown"
    end
    return CLIENT_IP
end

--[[
-- 获得用户头信息
 ]]
function get_user_agent()
    USER_AGENT = ngx.var.http_user_agent
    if USER_AGENT == nil then
        USER_AGENT = "unknown"
    end
    return USER_AGENT
end
--[[
--判断是否有上传文件
 ]]
function get_boundary()
    local header = ngx.req.get_headers()["content-type"]
    if not header then
        return false
    end
    if type(header) == "table" then
        header = header[1]
    end
    local match = string.match
    local m = match(header,".*boundary=.*")
    if m then
        return true
    end
    return false
end
--[[
--去除字符串两边空格
 ]]
function trim(s)
    return (string.gsub(s, "^%s*(.-)%s*$", "%1"))
end
--[[
--根据规则路径获得规则
 ]]
function get_rule(rulefilename)
    local io = require 'io'
    local RULE_PATH = config_rule_dir
    local RULE_FILE = io.open(RULE_PATH..'/'..rulefilename,"r")
    if RULE_FILE == nil then
        return
    end
    RULE_TABLE = {}
    for line in RULE_FILE:lines() do
        table.insert(RULE_TABLE,trim(line))
    end
    RULE_FILE:close()
    return(RULE_TABLE)
end


--[[
--记录日志到文件
 ]]
function log_record(method,url,data,ruletag)
    local LOG_PATH = config_log_dir
    local realIp = get_client_ip()
    local ua = get_user_agent()
    local servername = ngx.var.server_name;
    local time = ngx.localtime()
    if ua then
        line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\"  \""..ua.."\" \""..ruletag.."\"\n"
    else
        line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\" - \""..ruletag.."\"\n"
    end


    local LOG_NAME = LOG_PATH..'/'..ngx.today().."_waf.log"
    local file = io.open(LOG_NAME,"ab")
    if file == nil then
        return
    end
    file:write(line.."\n")
    file:flush()
    file:close()
end
--[[
--拦截后返回
 ]]
function waf_output()
    if config_waf_output == "redirect" then
        ngx.redirect(config_waf_redirect_url, 301)
    else
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(config_output_html)
        ngx.exit(ngx.status)
    end
end


