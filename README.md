# waf
使用Nginx+Lua实现自定义WAF（Web application firewall）

####功能列表：
1.	支持IP白名单和黑名单功能，直接将黑名单的IP访问拒绝。
2.	支持URL白名单，将不需要过滤的URL进行定义。
3.	支持User-Agent的过滤，匹配自定义规则中的条目，然后进行处理（返回403）。
4.	支持Cookie过滤，匹配自定义规则中的条目，然后进行处理（返回403）。
5.	支持URL过滤，匹配自定义规则中的条目，如果用户请求的URL包含这些，返回403。
6.	支持URL参数过滤，原理同上。
7.	支持日志记录，将所有拒绝的操作，记录到日志中去。

####WAF实现
   WAF一句话描述，就是解析HTTP请求（协议解析模块），规则检测（规则模块），做不同的防御动作（动作模块），并将防御过程（日志模块）记录下来。所以本文中的WAF的实现由五个模块(配置模块、协议解析模块、规则模块、动作模块、错误处理模块）组成。

####Nginx + Lua部署

环境准备
    [root@nginx-lua ~]# cd /usr/local/src
首先，现在Nginx安装必备的Nginx和PCRE软件包。
<pre>
[root@nginx-lua src]# wget http://nginx.org/download/nginx-1.9.4.tar.gz
[root@nginx-lua src]# wget ftp://ftp.csx.cam.ac.uk/pub/software/programming/pcre/pcre-8.37.tar.gz
</pre>
其次，下载当前最新的luajit和ngx_devel_kit (NDK)，以及春哥（章）编写的lua-nginx-module
<pre>
  [root@nginx-lua src]# wget http://luajit.org/download/LuaJIT-2.0.4.tar.gz
  [root@nginx-lua src]# wget https://github.com/simpl/ngx_devel_kit/archive/v0.2.19.tar.gz
  [root@nginx-lua src]# wget https://github.com/openresty/lua-nginx-module/archive/v0.9.16.tar.gz
</pre>

最后，创建Nginx运行的普通用户
   [root@nginx-lua src]# useradd -s /sbin/nologin -M www

解压NDK和lua-nginx-module
<pre>
    [root@openstack-compute-node5 src]# tar zxvf v0.2.19 解压后为ngx_devel_kit-0.2.19
    [root@openstack-compute-node5 src]# tar zxvf v0.9.10解压后为lua-nginx-module-0.9.16
</pre>

安装LuaJIT
Luajit是Lua即时编译器。
<pre>
  [root@openstack-compute-node5 src]# tar zxvf LuaJIT-2.0.3.tar.gz 
  [root@openstack-compute-node5 src]# cd LuaJIT-2.0.3
  [root@openstack-compute-node5 LuaJIT-2.0.3]# make && make install
</pre>

安装Nginx并加载模块
<pre>
  [root@openstack-compute-node5 src]# tar zxvf nginx-1.9.4.tar.gz 
  [root@openstack-compute-node5 src]# cd nginx-1.9.4
  [root@openstack-compute-node5 nginx-1.9.4]# export LUAJIT_LIB=/usr/local/lib
  [root@openstack-compute-node5 nginx-1.9.4]# export LUAJIT_INC=/usr/local/include/luajit-2.0
  [root@openstack-compute-node5 nginx-1.9.4]# ./configure --prefix=/usr/local/nginx --user=www --group=www     --with-http_ssl_module --with-http_stub_status_module --with-file-aio --with-http_dav_module --add-module=../ngx_devel_kit-0.2.19/ --add-module=../lua-nginx-module-0.9.16/ --with-pcre=/usr/local/src/pcre-8.37 
  [root@openstack-compute-node5 nginx-1.5.12]# make -j2 && make install

  [root@openstack-compute-node5 ~]# ln -s /usr/local/lib/libluajit-5.1.so.2 /lib64/libluajit-5.1.so.2
</pre>
如果不创建符号链接，可能出现以下异常：
error while loading shared libraries: libluajit-5.1.so.2: cannot open shared object file: No such file or directory

#####测试安装
安装完毕后，下面可以测试安装了，修改nginx.conf 增加第一个配置。
<pre>
        location /hello {
                default_type 'text/plain';
                content_by_lua 'ngx.say("hello,lua")';
        }
    
[root@openstack-compute-node5 ~]# /usr/local/nginx-1.9.4/sbin/nginx –t
[root@openstack-compute-node5 ~]# /usr/local/nginx-1.9.4/sbin/nginx
</pre>

然后访问http://xxx.xxx.xxx.xxx/hello，如果出现hello,lua。表示安装完成,然后就可以。
####WAF部署

<pre>
#cd /usr/local/nginx/conf
#git clone https://github.com/tluolovembtan/jsh_waf


修改Nginx的配置文件，加入以下配置。注意路径，同时WAF日志默认存放在/tmp/日期_waf.log
#WAF
    lua_shared_dict limit 50m;
    lua_package_path "/usr/local/openresty/nginx/conf/jsh_waf/?.lua";
    init_by_lua_file "/usr/local/openresty/nginx/conf/jsh_waf/init.lua";
    access_by_lua_file "/usr/local/openresty/nginx/conf/jsh_waf/waf.lua";

[root@openstack-compute-node5 ~]# /usr/local/nginx/sbin/nginx
</pre>
