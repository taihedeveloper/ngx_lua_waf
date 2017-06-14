# ngx_lua_waf
## 概述：
基于https://github.com/loveshell/ngx_lua_waf 做了重写<br>
由于原代码中存在大量的全局变量，在并发访问过程中变量的值极容易被覆盖，因而会导致某些该拦截的请求被放过，或某些正常请求被拦截的情况，因此重写了原代码<br>
同时，修改了原代码中的一些细节bug，并完善了部分拦截的逻辑<br>
欢迎大家批评指正，同时感谢@loveshell大神的源码<br>

## 使用说明：
需安装openresty之后方可使用<br>
假设nginx配置的路径为：<br>
/home/work/odp/webserver/conf<br>
openresty的lib库路径为：<br>
/home/work/odp/webserver/lualib<br>
则将waf包解压至：<br>
/home/work/odp/webserver/lualib<br>
并且在nginx配置文件中加上：<br>
lua_package_path '/home/work/odp/webserver/lualib/waf/?.lua;';<br>
lua_shared_dict limit 50m;<br>
lua_shared_dict iplimit 20m;<br>
init_by_lua_file /home/work/odp/webserver/lualib/waf/wafinit.lua;<br>
access_by_lua_file /home/work/odp/webserver/lualib/waf/wafindex.lua;<br>
如果nginx中还有其他的lua库需配置在lua_package_path中，则以分号分隔路径即可<br>

## 配置规则目录：
RulePath = "/home/work/odp/webserver/lualib/waf/wafconf"<br>
可为绝对路径或相对路径，相对路径由nginx启动脚本决定<br>
之后重启nginx生效<br>

## 配置文件说明：
wafconfig.lua:<br>
RulePath = "./lualib/waf/wafconf/", -- 匹配规则路径<br>
attacklog = "on", -- 是否开启日志<br>
logdir = "./logs/hack/", -- 日志目录<br>
UrlDeny = "on", -- 是否检测url<br>
CookieMatch = "on", -- 是否检测cookie<br>
postMatch = "on", -- 是否检测post参数<br>
whiteModule = "on", -- 是否检测url白名单<br>
black_fileExt = {"php", "jsp"}, -- 上传文件后缀检测<br>
ipWhitelist = {"127.0.0.1"}, -- 白名单ip列表，支持*做正则<br>
ipBlocklist = {"1.0.0.1"}, -- 黑名单ip列表，支持*做正则<br>
CCDeny = "off", -- 是否做cc防攻击检测<br>
CCrate = "100/60", -- ip访问特定url频率（次/秒）<br>
ipCCrate = "600/60", -- ip访问服务器频率（次/秒）<br>

wafconf中的拦截规则沿用源码中的配置，和业界当前的拦截匹配规则基本一致<br>

## 检测方式：
访问http://ip:port/xxxx.php?id=../etc/passwd 后显示403 forbidden即配置生效<br>

最后再次感谢@loveshell大神的waf代码，这一版的代码思路基本全部源自于其git的waf代码，只是在其思路基础上做了lua代码的规范完善+bug修复+部分规则的加强。
