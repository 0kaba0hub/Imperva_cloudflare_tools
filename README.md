# Imperva_cloudflare_tools

update_ips.py - the python script for manage Imperva or Cloudflare proxy IPs for apache | f5 big ip whitelisting and proxy IPs for get real client IPs in logs

## What need to configure in general

### 1. rename config.ini-example to config.ini and fill settings

Email section - for sending email notifications if something wrong
Flock section - settings for Flock chanel notification
Files section - files location for apache2 for the list of proxy IPs
                We recomended to create directory /etc/apache2/remoteip/
                Than add changes to remoteip.conf:

               <IfModule remoteip_module>
                  RemoteIPHeader X-Forwarded-For
                  RemoteIPInternalProxy 10.xxx.xxx.xxx/24
                  RemoteIPTrustedProxyList /etc/apache2/remoteip/ip.txt
               </IfModule>

Apache section - check your apache reload command 
Logging section - log file location and debug options. We recomended to use debug on the setup steps
F5 section - if you have F5 BIG IP LB behind your ifrastructure 

### 2. run test job
Example:
```bash
/usr/local/src/imperva_cloudflare/update_ips.py cloudflare apache
```

### 3. check logs
Example:
```bash
2024-12-24 13:10:01,645 - INFO - Selected provider: Cloudflare
2024-12-24 13:10:01,645 - DEBUG - Start cloudflare_process_ip_ranges()
2024-12-24 13:10:01,645 - DEBUG - SMTP is disabled.
2024-12-24 13:10:01,647 - DEBUG - Starting new HTTPS connection (1): api.cloudflare.com:443
2024-12-24 13:10:01,727 - DEBUG - https://api.cloudflare.com:443 "GET /client/v4/ips HTTP/1.1" 200 None
2024-12-24 13:10:01,731 - DEBUG - Received a successful response from API.
2024-12-24 13:10:01,731 - DEBUG - API response indicates success.
2024-12-24 13:10:01,732 - DEBUG - Old IPv4 ranges: ['173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22']
2024-12-24 13:10:01,732 - DEBUG - New IPv4 ranges: ['173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22']
```

### 4. create cronjob
Example:
```bash
5-55/5 * * * *  root /usr/local/src/imperva_cloudflare/update_ips.py cloudflare apache
```

### 5. turn off debug

### 6. enable on F5 HTTP(s) vhost side irule HTTP-ADD-HEADER-XForwardFor on top

Run to fill IPs for F5 balancer:
```bash
/usr/local/src/imperva_cloudflare/update_ips.py cloudflare f5
```

### 7. configure Apache custom logs
```bash
LogFormat "%v:%p %a %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined
CustomLog /var/log/apache2/access.log vhost_combined
```