--
-- 作者: Bruce
-- 日期: 2016/10/20
-- 模仿:ngx_lua_waf
-- 版权:MIT License
-- 书写书序：先检查白名单，通过即不检测；再检查黑名单，不通过即拒绝，检查UA，UA不通过即拒绝；检查cookie；URL检查;URL参数检查，post检查；
--
require 'init'
function waf_main()
    if while_ip_check() then --第一层 允许白名单过
    elseif black_ip_check() then --第二层 拦截黑名单IP
    elseif user_agent_attack_check() then --第三层 拦截黑名单user_agent
    elseif cookie_attack_check() then --第四层 拦截黑名单cookie
    elseif white_url_check() then  -- 第五层 放过白名单url
    elseif black_url_check() then  --第六层 拦截黑名单url
    elseif url_attack_check() then  --第七层 过来URL路径
    elseif url_args_attack_check() then --第八层 url参数检查
    elseif post_attack_check() then --第九层 post提交的参数检查
    elseif upload_file_check() then --第十层 upload拦截一句话
    else
        return
    end
end
--ngx.header.content_type = "text/html" --设置编码
--ngx.say("in waf")
local is_waf_status = waf_enable()
if is_waf_status then
    waf_main()
end