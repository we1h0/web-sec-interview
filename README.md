 # web-sec-interview
 - [ ] 介绍一下自认为有趣的挖洞经历（或CTF经历）
 
 - [ ] 你平时用的比较多的漏洞是哪些？相关漏洞的原理？以及对应漏洞的修复方案？
 
 - [ ] xss漏洞打到后台登陆地址为内网IP,你会如何处理？
 
 - [ ] 说说常见的中间件解析漏洞利用方式  
 
 - [ ] java反序列化漏洞的原理?解决方案?
 
 - [ ] 如果一台服务器被入侵后,你会如何做应急响应?
 
 - [ ] 你平时使用哪些工具?以及对应工具的特点?
 
 - [ ] 如果遇到waf的情况下如何进行sql注入/上传Webshell怎么做？请写出曾经绕过WAF的经过(SQLi，XSS，上传漏洞选一) 
 
    <a href="https://xz.aliyun.com/t/265/">我的WafBypass之道（SQL注入篇）</a>
  
    <a href="https://xz.aliyun.com/t/337/">我的WafBypass之道（Upload篇）</a>
  
    <a href="https://xz.aliyun.com/t/265/">我的WafBypass之道（Misc篇）</a>
  
 - [ ] 介绍 SQL 注入漏洞成因，如何防范？注入方式有哪些？除了数据库数据，利用方式还有哪些？
 
 - [ ] 如何防范 XSS 漏洞，在前端如何做，在后端如何做，哪里更好，为什么？
 
 - [ ] 如何绕过CDN获取目标网站真实IP，谈谈你的思路？  
 
 - [ ] 如果给你一个网站,你的渗透测试思路是什么?
 在获取书面授权的前提下。 
 - 1)信息收集， 
 - 1，获取域名的whois信息,获取注册者邮箱姓名电话等。 
 - 2，查询服务器旁站以及子域名站点，因为主站一般比较难，所以先看看旁站有没有通用性的cms或者其他漏洞。 
 - 3，查看服务器操作系统版本，web中间件，看看是否存在已知的漏洞，比如IIS，APACHE,NGINX的解析漏洞 
 - 4，查看IP，进行IP地址端口扫描，对响应的端口进行漏洞探测，比如 rsync,心脏出血，mysql,ftp,ssh弱口令等。 
 - 5，扫描网站目录结构，看看是否可以遍历目录，或者敏感文件泄漏，比如php探针 
 - 6，google hack 进一步探测网站的信息，后台，敏感文件
 - 2）漏洞扫描 
 - 开始检测漏洞，如XSS,XSRF,sql注入，代码执行，命令执行，越权访问，目录读取，任意文件读取，下载，文件包含， 
 远程命令执行，弱口令，上传，编辑器漏洞，暴力破解等 
 - 3）漏洞利用 
 - 利用以上的方式拿到webshell，或者其他权限 
 - 4）权限提升 <br>
 - 提权服务器，比如windows下mysql的udf提权，serv-u提权，windows低版本的漏洞，如iis6,pr,巴西烤肉， 
 - linux藏牛漏洞，linux内核版本漏洞提权，linux下的mysql system提权以及oracle低权限提权 
 - 5）日志清理 <br>
 - 6）总结报告及修复方案<br>
 
 - [ ] 谈一谈Windows系统与Linux系统提权的思路？  
 
 - [ ] Windows、Linux、数据库的加固降权思路，任选其一  
 
 - [ ] 列举出您所知道的所有开源组件高危漏洞(十个以上)  
 
 - [ ] 反弹 shell 的常用命令？一般常反弹哪一种 shell？为什么？
 
 - [ ] 描述一个你深入研究过的 CVE 或 POC。
 
 - [ ] CSRF 和 XSS 和 XXE 有什么区别，以及修复方式？ 
 
 - [ ] CSRF、SSRF和重放攻击有什么区别？ 
 
 - [ ] 说出至少三种业务逻辑漏洞，以及修复方式？ 
 
 - [ ] 发现 demo.jsp?uid=110 注入点，你有哪几种思路获取 webshell，哪种是优选？ 
 
 - [ ] 以下链接存在 sql 注入漏洞，对于这个变形注入，你有什么思路？ 
 > demo.do?DATA=AjAxNg== 
 
 - [ ] CMD命令行如何查询远程终端开放端口
 
 - [ ] 服务器为IIS+PHP+MySQL，发现root权限注入漏洞，讲讲你的渗透思路  
 
 - [ ] 说出XSS的三种类型，且在过滤”<>”号下如何绕过  
 
 - [ ] 请写出Mysql5数据库中查询库’helloworld’中’users’表所有列名的语句  
 
 - [ ] 下面这段代码存在漏洞吗？如果存在请说出存在什么漏洞并利用  
 >     http://www.exp.com/1.php  
 >     <?php  
 >     $s_func = $_GET[‘s_func’];
 >     $info = $_GET[‘info’];
 >     $s_func($info);
 >     ?>

 - [ ] 菜刀被waf拦截后要怎么处理?
 
      <a href="https://xz.aliyun.com/t/2739/">菜刀HTTP流量中转代理过WAF</a>
   
 - [ ] sqlmap如何对一个注入点注入?
  - 如果是get型，直接，sqlmap -u “诸如点网址”. 
  - 如果是post型，可以sqlmap -u “注入点网址” –data=”post的参数” 
  - 如果是cookie，X-Forwarded-For等，可以访问的时候，用burpsuite抓包，注入处用*号替换，放到文件里，然后sqlmap -r “文件地址”

