--
-- Created by IntelliJ IDEA.
-- Author: Bruce
-- Date: 2016/10/21
-- waf 控制器
--
require '__config'
require '__lib'

local rulematch = ngx.re.find --nginx 正则
local unescape = ngx.unescape_uri --uri编码解码

--[[
--是否开启应用防火墙
 ]]
function waf_enable()
    if config_waf_enable ~= nil and config_waf_enable == "on" then
        return true
    else
        return false
    end
end
--[[
-- 放行白名单
 ]]
function while_ip_check()
    if config_white_ip_check == "on" then
        local IP_WHITE_RULE = get_rule('whiteip.rule')
        local WHITE_IP = get_client_ip()
        if IP_WHITE_RULE ~=nil then
            for _, rule in pairs(IP_WHITE_RULE) do
                if rule ~="" and rulematch(WHITE_IP, rule, "isjo")then
                    return true
                end
            end
        end
    end
    return false
end
--[[
-- 拦截黑名单
 ]]
function black_ip_check()
    if config_black_ip_check == "on" then
        local IP_BLACK_RULE = get_rule('blackip.rule')
        local BLACK_IP = get_client_ip()
        if IP_BLACK_RULE ~=nil then
            for _, rule in pairs(IP_BLACK_RULE) do
                if rule ~= "" and rulematch(BLACK_IP,rule,"isjo") then
                    log_record('BlackList_IP',ngx.var.request_uri,"-",rule)
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end
--[[
-- 拦截黑名单头信息
 ]]
function user_agent_attack_check()
    if config_user_agent_check == "on" then
        local USER_AGENT_RULES = get_rule('useragent.rule')
        local USER_AGENT = get_user_agent()
        if USER_AGENT ~= nil then
            for _,rule in pairs(USER_AGENT_RULES) do
                if rule ~="" and rulematch(USER_AGENT,rule,"isjo") then
                    log_record('Deny_USER_AGENT',ngx.var.request_uri,"-",rule)
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end
--[[
--拦截黑名单cookie
 ]]
function cookie_attack_check ()
    if config_cookie_check == "on" then
        local COOKIE_RULES = get_rule('cookie.rule')
        local USER_COOKIE = ngx.var.http_cookie
        if USER_COOKIE ~= nil then
           for _,rule in pairs(COOKIE_RULES) do
               if rule ~="" and rulematch(USER_COOKIE,rule,"isjo") then
                   log_record('Deny_Cookie',ngx.var.request_uri,"-",rule)
                   waf_output()
                   return true
               end
           end
        end
    end
    return false
end
--[[
--放过白名单中的url
 ]]
function white_url_check()
    if config_white_url_check == "on" then
        local URL_WHITE_RULES = get_rule('whiteurl.rule')
        local REQ_URI = ngx.var.request_uri
        if URL_WHITE_RULES ~= nil then
            for _,rule in pairs(URL_WHITE_RULES) do
                if rule ~= "" and REQ_URI==rule then
                    return true
                end
            end
        end
    end
    return false
end
--[[
--拦截黑名单URL
 ]]
function black_url_check()
    if config_black_url_check == "on" then
        local URL_BLACK_RULES = get_rule('blackurl.rule')
        local REQ_URI = ngx.var.request_uri
        if URL_BLACK_RULES ~= nil then
            for _,rule in pairs(URL_BLACK_RULES) do
                if rule ~= "" and REQ_URI==rule then
                    log_record('Deny_URL',REQ_URI,"-",rule)
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end
--[[
--url路径检查
 ]]
function url_attack_check()
    if config_url_check == "on" then
        local URL_RULES = get_rule('url.rule')
        local REQ_URI = ngx.var.request_uri
        for _,rule in pairs(URL_RULES) do
            if rule ~="" and rulematch(unescape(REQ_URI),rule,"isjo") then
                log_record('Deny_URL',REQ_URI,"-",rule)
                waf_output()
                return true
            end
        end
    end
    return false
end
--[[
--url参数检查
 ]]
function url_args_attack_check()
    if config_url_args_check == "on" then
        local ARGS_RULES = get_rule('args.rule')
        for _,rule in pairs(ARGS_RULES) do
            local REQ_ARGS = ngx.req.get_uri_args()
            if REQ_ARGS ~= nil then
                for key, val in pairs(REQ_ARGS) do
                    if type(val) == "table" then
                        ARGS_DATA = table.concat(val, " ")
                    else
                        ARGS_DATA = val
                    end
                    if ARGS_DATA and type(ARGS_DATA) ~= "boolean" and rule ~="" then
                         if rulematch(unescape(ARGS_DATA),rule,"isjo") then
                             waf_output()
                             return true
                         end
                    end
                end
            end
        end
    end
    return false
end
--[[
--过滤POST参数
 ]]
function post_attack_check()
    local method=ngx.req.get_method()
    if config_post_check == "on" and method == "POST" then
        local boundary = get_boundary()
        if boundary then
            --这是文件上传
            local POST_ARGS =ngx.req.get_body_data()
            local FILE_RULES = get_rule('file.rule')
            if rulematch(POST_ARGS,"(.php|.java)","isjo") then
                waf_output()
                return true
            end
        else
            --这是表单提交
            local POST_RULES = get_rule('post.rule')
            if POST_RULES ~= nil then
                for _,rule in pairs(POST_RULES) do
                    local POST_ARGS =ngx.req.get_body_data()
                    if POST_ARGS ~=nil then
                        if rulematch(unescape(POST_ARGS),rule,"isjo") then
                            waf_output()
                            return true
                        end
                    end
                end
            end
        end

    end
    return false
end

