 # web-sec-interview

Information Security Industry Practitioners (Web Security / Penetration Testing) Interview Questions 1.1

### README English | [中文](README_CN.md)

---

   * Introduce the experience of burrowing (or CTF experience) that you think is interesting

   * What are the more vulnerabilities you usually use? The principle of related vulnerabilities? And a fix for the vulnerability?

   * What tools do you usually use and the characteristics of the corresponding tools?
 
   * How to do sql injection / upload Webshell if you encounter waf? Please write the process of bypassing WAF (SQLi, XSS, upload vulnerability)
   
     Refer to the following three
    
  <a href="https://xz.aliyun.com/t/265/">My Way of WafBypass (SQL Injection)</a><br />
  <a href="https://xz.aliyun.com/t/337/">My Way of WafBypass (Upload)</a><br />
  <a href="https://xz.aliyun.com/t/265/">My Way of WafBypass (Misc)</a><br />

   * Talk about the idea of ​​lifting the rights of Windows system and Linux system?
 
   * List all high-risk vulnerabilities of open source components that you know (more than ten)
 
   * Describe a CVE or POC that you have studied in depth.
 


* SQLi
   * How to judge sql injection, what are the methods?
    > Add single quotes, double quotes, order by, rlike, sleep, benchmark, operator, modify data type, error injection statement test
   
   * Introduce the cause of SQL injection vulnerabilities, how to prevent it? What are the injection methods? In addition to database data, what are the ways to use it?
   
   * The principle of wide character injection? How to use the wide character injection vulnerability, how to construct and repair the payload?
    > Popularly speaking, gbk, big5 and other codes account for two bytes. After the sql statement enters the backend, the single quotes are escaped. The escaped \ is %5C, and the current %xx and %5C can be combined into two. When the characters are in bytes, the subsequent single quotes can escape, resulting in injection. More common gbk, %df' =>
%df%5c%27 => 运'. Already single quotes, the rest is almost the same as normal injection.
    > Fix the way by setting the MYSQL database character set utf8mb4, PHP character set utf-8.

   * You all know which sql pass skills
    > This is too much, a lot of online search. Mainly depends on the filtering and protection of the target site. Common bypass can be /**/ replace spaces, /*!00000union*/ is equal to union, or use front-end filtering, add angle brackets <>. Cases are too common. If you filter functions or keywords, you can try other equivalent functions that can achieve results. Keywords such as or 1=1 can be replaced with ||1, or with operators such as /, %. The same effect. In short, still look at the requirements.


   * How does sqlmap inject an injection point?
    > If it is get type, directly, sqlmap -u "injection point URL".
    >
    > If it is post type, you can sqlmap -u "injection point URL" -data="post parameter"
    >
    > If it is a cookie type, X-Forwarded-For, etc., when you can access it, use Burpsuite to capture the package, replace it with the * mark, put it in the file, and then sqlmap -r "file address"
    
   * mysql website injection, what is the difference between 5.0 and below?
    > Below 5.0, there is no information_schema system table, can not list names, etc., can only violently run table names.
    > 5.0 is multi-user single operation, 5.0 or more is multi-user and multi-operation.
    
   * mysql injection point, use the tool to write a sentence directly to the target station, what conditions are needed?
    > root permissions and the absolute path to the site.
   
   * There is a sql injection vulnerability in the following link. What ideas do you have for this variant injection?
   > demo.do?DATA=AjAxNg==
 
   * Found demo.jsp?uid=110 injection point, what kinds of ideas do you have to get webshell, which is the best?

* Domain
   * Explain the same-origin policy
    > If the protocol of the two pages, the port and the domain name are the same, it can be considered to be homologous.
   
   * The same-origin strategy, those things are acquired by homology
    > read cookies, LocalStorage and IndexDB
    > read DOM elements
    > Send an AJAX request
    >
   * If the subdomain and the top-level domain have different sources, where can I set them to be homologous?
    > Probably the same subdomain, the main domain has different meanings, you can solve the cross-domain by setting document.domain in both rooms.
   * How to set up data that can be requested across domains? What does jsonp do?
    > When the primary domain is the same, cross-domain, you can set document.domain as above.
    >
    > When the primary domain is different, you can set up CORS on the server to make cross-domain requests through jsonp and websocket. H5 added the window.postMessage method to resolve cross-domain requests.
    >
    > Request json data via <script> like server, not subject to the same-origin policy.

   * What is the business meaning of jsonp?
   
* Ajax
   * Does Ajax follow the same-origin policy?
    > The full name of ajax is Asynchronous JavaScript and XML, asynchronous javascript and XML technology. Follow the same-origin policy, but can be circumvented by jsonp, etc.
    
   * How to use JSON injection?
    > XSS cross-site attack
    
   * What is the difference between JSON and JSONP?
   * JSONP hijacking utilization and repair plan?

* Browser strategy
   * What are the security policies between different browsers, such as chrome, firefox, IE
    > All three browsers follow the same-origin policy, Content Security Policy (CSP), Cookie Security Policy (httponly, Secure, Path)
    
   * What is CSP? How to set up CSP?
   > CSP: Content Security Policy, content security policy. It is a security mechanism for breeding XSS attacks. The idea is to configure trusted content sources in the form of server whitelists, which can be used by client web application code.

* XSS
   * What is XSS and how is it repaired?
    > XSS is a cross-site scripting attack, in which data submitted by users can be constructed to execute, thus stealing user information and other attacks. Fixing method: Escape character entities, use HTTP Only to prohibit JavaScript from reading cookie values, check on input, and use the same character encoding for browser and web application.
   * What happened to xss?
    > Personal understanding is to safely filter the data submitted by the user and then directly input into the page, causing the execution of the js code. As for the specific scene, there is a risk that the output may be affected by xss.
   * XSS persistence?
   * If you are given an XSS vulnerability, what additional conditions do you need to construct a worm?
    > XSS worm: XSS attacks can cause mutual infections among users in the system, causing the entire system user to fall, and the XSS vulnerability that can cause this harm becomes an XSS worm.
    >
    > 1. Construct a self-replicating reflective XSS
    >
    > 2, insert comments, message box
    >
    > 3. The user clicks on the link and the link content points to the same XSS vector. That is, the page of the stored type xss injected into the worm code. When the link is clicked, it will continue to cause the worm to spread.
   * Where can a worm appear on social networking sites?
    >Message Board/Comment/Article Post/Private Message...
   * If you are called to defend against worms, what methods do you have?
    > 1. Change the name of the local destructive program.
2. Close the executable file.
3. Prohibit "FileSystemObject" to effectively control the spread of VBS virus. Specific operation method: Use regsvr32 scrrun.dll /u this command to disable file system objects.
4. Open the browser's security settings.
   * If you are given an XSS blind hit vulnerability, but the information returned shows that his background is on the intranet and can only be accessed using intranet, how do you use this XSS?
    > github has some ready-made xss scripts for scanning intranet ports, which can be used for reference, and then further utilized according to the detected information, such as opening redis, etc., and then using the vulnerability to getshell.
   * How to prevent XSS vulnerabilities, how to do it in the front end, how to do it in the back end, where is better, and why?
   * How does the black box detect XSS vulnerabilities?

* CRLF injection
  * Principle of CRLF injection
    > CRLF is the abbreviation for carriage return + line feed. I have encountered relatively few, and I have never dug through such a hole. In short, it is generally possible to control the response of the server by submitting a malicious data containing a carriage return and a line feed. I have encountered potential CRLF after submitting a carriage return and a new line. The use of CRLF can be XSS, malicious redirect location, and set-cookie.

* CSRF
   * What is CSRF? How to fix it?
    > CSRF is a cross-site request forgery attack. XSS is one of many means of implementing CSRF because there is no confirmation that the user is voluntarily initiated when the critical operation is performed. Fix: Filter out the pages that need to be protected and embed the Token, enter the password again, and verify the Referer.
   * What is the nature of the CSRF vulnerability?
    > CSRF is a cross-site request forgery that sends a request to the server as a victim. In essence, the individual feels that the server does not check the identity of the user who submitted the operation while performing some sensitive operations.
  * What are the methods to defend against CSRF? How does JAVA defend against CSRF vulnerabilities? Is token useful?
   > Defense CSRF is generally plus referer and csrf_token.
   > For details, please refer to this <a href="https://www.ibm.com/developerworks/cn/web/1102_niugang_csrf/index.html">CSRF attack response to CSRF attacks</a>
   
  * What is the difference between CSRF, SSRF and replay attacks?
   > CSRF is a cross-site request forgery attack initiated by the client
   >
   > SSRF is server-side request forgery, initiated by the server
   >
   > Replay attack is to replay the intercepted data packets for identity authentication and other purposes.

* SSRF
  * SSRF vulnerability principle, utilization and repair plan? What is the difference between Java and PHP SSRF?

* Logical Vulnerabilities
   * Say at least three business logic vulnerabilities and how to fix them?
    > 1) The password recovery vulnerability exists in the password to allow brute force cracking, the existence of universal recovery documents, the ability to skip the verification step, the recovery of the voucher can be obtained, etc. to obtain the password through the password recovery function provided by the manufacturer.
    >
    > 2) The most common authentication vulnerability is session fixed attack and cookie spoofing. You can fake user identity by getting Session or Cookie.
    >
    > 3) The verification code exists in the verification code vulnerability to allow brute force cracking, and the verification code can be bypassed by Javascript or packet modification.

* Override access (horizontal/vertical/unauthorized)
 * Talk about the difference between horizontal/vertical/unauthorized unauthorized access?
 * How to detect the violation of power?

* XML injection
 * What is XXE? What is the repair plan?
  * XXE is an XML external entity injection attack. XML can request local or remote content by calling an entity. Similar to remote file protection, it can cause related security issues, such as sensitive file reading. Repair method: The XML parsing library strictly prohibits the parsing of external entities when called.

* URL redirection
 * URL whitelist bypass

* HTML5
   * Talk about the new security features of HTML5
    > H5 has added a lot of tags and has a lot of options to bypass the xss defense. There is also the addition of local storage, localstorage and session storage, which can be modified by xss to achieve a similar storage xss effect.
<code>
<video onerror=alert(1)><source>
<video><sourceonerror="javascript:alert(1)"
<video src=".." onloadedmetadata="alert(1)" ondurationchanged="alert(2)" ontimeupdate="alert(3)"></video>
<video><sourceonerrorsourceonerrorsourceonerrorsourceonerror="javascript:alert(1)">
<videopostervideopostervideopostervideoposter=”javascript:alert(1)”>
</code>
   * What tags should be included in the HTML5 whitelist?
See <a href="https://segmentfault.com/a/1190000003756563">HTML5 Security Issues</a>

* java
   * What java framework do you know about?
    > struts2 , spring, spring security, shiro, etc.
    >
   * What is the MVC structure of java, and what is the order of data flow to the database?
   * Understand the java sandbox?
   * Can ibats' parameterized query control sql injection effectively? Is there a dangerous way to cause sql injection?
   * Talk about the principle of two struts2 vulnerabilities
   * What role does ongl play in this payload?
   * What is the hexadecimal encoding of the character \u0023? Why use him in the payload?
   * Does java vulnerabilities occur when executing system commands? What statements are there in java, methods can execute system commands
   * If you are asked to fix an xss vulnerability, will you fix it in that layer of the java program?
   * Where is the xss filter set in the java program?
   * Say what problems may exist in the security of java class reflections
   * The principle of Java deserialization vulnerability? Solution?

* PHP
   * What methods are available in php to prevent errors from being echoed?
    > php's configuration file php.ini has been modified. When display_errors = On is changed to display_errors = off, there is no error message.
    > Add error_reporting(0) at the beginning of the php script; it can also achieve the effect of closing the error.
    > In addition to the above, you can also add @ in front of the execution statement
   * What security features can be set by php.ini
   
    > Close the error, set open_basedir, disable the dangerous function, open gpc. There is a specific article on the security configuration, which belongs to the scope of operation and maintenance.
    >
   * What is the principle of php's %00 truncation?
   
    > Exist in version 5.3.4, generally use the truncation of the file name when the file is uploaded, or there may be a 00 stage when the file is operated. For example, filename=test.php%00.txt will be truncated to test.php, and 00 is ignored. When the system reads the file name, if it encounters 0x00, it will consider that the reading has ended.
    >
   * php webshell detection, what are the methods?
    > Personally, there are two types of static detection and dynamic detection. Static detection, such as finding dangerous functions, such as eval, system, etc. Dynamic detection is the action to be performed when the script is running, such as file operations, socket operations, and so on. The specific method can be detected by D shield or other killing software, and now there is webshell recognition based on machine learning.
    >
   * php LFI, what is the principle of local vulnerability? Write a code with a vulnerability. How to find out by hand? How do you traverse the file if there is no error returning?
   * The principle of php deserialization vulnerability? Solution?

* Middleware
   * What security hardening does tomcat do?
   * If tomcat restarts, under webapps, will the background you delete be back again?
   * Common web server middleware container.
    > IIS, Apache, nginx, Lighttpd, Tomcat
    >
    * What are the more common middleware containers in JAVA?
    > Tomcat/Jetty/JBOSS/WebLogic/Coldfusion/Websphere/GlassFish
   * Talk about common middleware parsing exploits
    > IIS 6.0
     > /xx.asp/xx.jpg "xx.asp" is the folder name
     >
    > IIS 7.0/7.5
    > Default Fast-CGI is enabled. Enter /1.php directly after the image address in the url, and the normal image will be parsed as php.
    >
    > Nginx
     > The version is less than or equal to 0.8.37. The method is the same as IIS 7.0/7.5, and the Fast-CGI can be used when it is closed.
     > empty byte code xxx.jpg%00.php
     >
    > Apache
     > The uploaded file is named test.php.x1.x2.x3, and Apache is suffixed from right to left.
     >
    > lighttpd
     > xx.jpg/xx.php
     >
   * How does Redis' unauthorized access vulnerability exploit?

* Database
   * What is the difference between MySQL UDF and 5.1 and above, and what are the conditions?
   
   > 1) Mysql version is larger than 5.1 version udf.dll file must be placed in the lib\plugin folder under the MYSQL installation directory.
   >
   > 2) Mysql version is less than version 5.1. The udf.dll file is placed in c:\windows\system32 under Windows 2003 and c:\winnt\system32 under windows2000.
   >
   > 3) Master the mysql database account has the mysql insert and delete permissions to create and discard the function, generally the root account is better, with the other accounts of the root account can also be used.
   >
   > 4) Permission to write udf.dll to the appropriate directory.

   * What libraries are available by default in the mysql database? Say the name of the library
   
    > infomation_schema, msyql, performance_scheme, test
    >
   * mysql username and password are stored in that table? What encryption method does mysql password use?
    > The user table under the mysql database.
    >
   * mysql table permissions, in addition to additions and deletions to change the check, file read and write, what permissions?
   * How to do mysql security?
   * How to private sqlserver public permission
   * Windows, Linux, database reinforcement and power reduction ideas, choose one

* Linux
   * Briefly describe what needs to be done for Linux system security hardening
   * What tools do you use to determine if the system has a back door?
   * What is Selinux for Linux? How to set up Selinux?
   * Which layer of iptables work in the TCPIP model?
   * If the kernel cannot be upgraded, how can I ensure that the system is not authorized by the known exp?
   * What are the logs in syslog? Where to find the log of the installation software?
   * How to query the login log of ssh? How to configure the log format of syslog?
   * Can syslog be viewed directly using tools such as vi? Is it a binary file?
   * How do you respond to an emergency if a Linux server is compromised?
   * Common commands for bounce shells? Which kind of shell does it usually rebound? why?

* Emergency Response
  * What kinds of backdoor implementations are there?
  * What is the idea of ​​webshell detection?
  * After the Trojan in the Linux server, please briefly describe the emergency ideas?
  * How should I respond to an emergency after encountering a new 0day\ (such as Struts2\)?
  * In which directions can the security assessment be conducted before the new business goes online?
  * From which directions can the existing system be audited to find out the security risks?

* Information Collection
   * What information is collected when you step on the point?
   * The role of DNS in penetration
   * How to get around the CDN to get the real IP of the target website, talk about your ideas?
 
    <a href="https://zhuanlan.zhihu.com/p/33440472">Summary of ways to bypass the CDN to find real IP on the site</a>
    
   * If you are given a website, what is your penetration testing idea?
Subject to written authorization

    * 1. Information collection
    > 1) Obtain the whois information of the domain name, obtain the registrant's email name and phone number.
    >
    > 2) Query the server side station and the sub-domain name site, because the main station is generally difficult, so first look at the side stations for general-purpose cms or other vulnerabilities.
    >
    > 3) View the server operating system version, web middleware, to see if there are known vulnerabilities, such as IIS, APACHE, NGINX parsing vulnerabilities
    >
    > 4) View the IP, perform an IP address port scan, and perform vulnerability detection on the responding port, such as rsync, heart bleeding,
     Mysql, ftp, ssh weak password, etc.
    > 5) Scan the site directory structure to see if you can traverse the directory, or sensitive file leaks, such as php probe
    >
    > 6) google hack further probes website information, background, sensitive files
    
    * 2. Vulnerability scanning
    > Start detecting vulnerabilities such as XSS, CSRF, SQL injection, code execution, command execution, unauthorized access, directory read, arbitrary file read,
     Download, file contains, remote command execution, weak password, upload, editor vulnerability, brute force, etc.
    * 3. Exploitation
    > Get the webshell or other permissions using the above method
    * 4. Privilege promotion
    > Elevate the server, such as mysql udf privilege under windows, serv-u privilege, windows low version of the vulnerability, such as iis6, pr,
     Brazilian barbecue
    > linux dirty cow vulnerability, linux kernel version vulnerabilities, mysql root privilege under linux and oracle low privilege
    * 5. Log cleaning
    * 6. Summary report and repair plan


   * In the infiltration process, what is the value of collecting the target station registrant mailbox for us?
   
    > 1) Drop the social library to see if there is any password leaked, and then try to log in to the background with the leaked password.
    >
    > 2) Use the mailbox as a keyword to throw into the search engine.
    >
    > 3) Use the searched related information to find other mails and get the common social accounts.
    >
    > 4) Social workers find social accounts, which may find the administrator's habit of setting passwords.
    >
    > 5) Use the existing information to generate a dedicated dictionary.
    >
    > 6) Observe what non-popular websites the administrator often visits, take it, and you will get more good things.
    
   * What is the significance of determining the CMS of the website for infiltration?
   
    > 1) Find vulnerable bugs on the web.
    >
    > 2) If open source, you can also download the corresponding source code for code auditing.
    >
    > 3) A mature and relatively safe CMS, the meaning of sweeping the catalog when infiltrating?
    >
    > 4) sensitive files, secondary directory scanning
    >
    > 5) The misoperation of the webmaster such as: compressed files of the website backup, description.txt, secondary directory may store other sites
