The code is inspired by https://github.com/anthonymartin/aws-acl-fail2ban which bans/unbans IPs using AWS Network ACL.

**Currently AWS WAF v2 is supported in master branch and >= v2.0.0 includes functionality only for AWS WAF v2. If you need the script to work with AWS WAF v1, please check the tag v1.0.0.**

# fail2ban-aws-wafv2

This package includes a script and fail2ban configuration that allows you to use fail2ban when utilizing AWS elastic load balancer (ELB) and an Nginx webserver. It is useful to protect your site against DoS and brute force attacks when behind a reverse proxy load balancer like ELB. Special consideration is required when using ELB with fail2ban because ELB only forwards the client IP to the server in an X-Forwarded-For header. Following this guide will enable you to use ELB, Nginx webservers and AWS WAF together with fail2ban for an dynamic firewall solution.
The code in this repository is rewritten in Python and uses AWS WAF IP Conditions to ban/unban IP from fail2ban.

Dependencies
------------

* AWS CLI must be installed and your access credentials must be setup as specified in AWS CLI docs (either through a ~/.aws/config or through an environment variable). ** IF someone would like to update the code to use AWS composer package, I'm sure that would make many people's lives easier **
* A WAF IP Sets rule must be created and associated with your application load balancer in AWS
* Make sure that the credentials you've configured in AWS for the AWS CLI allow read/write to WAF resources.
* Your nginx logs must log the X-Forwarded-For header instead of the ELB IP address. Instructions on how to do so are found below.

Installation
-----

For now the only possibility to install the project is only to clone the repository.

Nginx configuration
-------------------

1. Enable nginx real_ip_module
2. Edit /etc/nginx/nginx.conf

```
http {
    ...
    real_ip_header X-Forwarded-For;
    set_real_ip_from 0.0.0.0/0;
    ...
}
```

The value for ```set_real_ip_from``` must be equal to a virtual IP of your load balancer (e.g. 172.66.0.0/16).

fail2ban Configuration
-----
1. Copy `fail2ban/action.d/aws-waf.conf` in `/etc/fail2ban/action.d/` directory
2. Copy `fail2ban/filter.d/aws-waf-example-filter.conf` to `/etc/fail2ban/filter.d/` directory
3. Update `actionban` and `actionunban` definitions in `/etc/fail2ban/action.d/aws-waf.conf`. You need to replace both instances of `/path/to/fail2ban_aws_waf.py` to the location of `fail2ban_aws_waf.py` script on your server. You should use the absolute path when updating `actionban` and `actionunban`.
4. Optionally you can leave the parameter `--logpath` and set the correct path to log directory (it will contain logs about AWS API operations). Otherwise remove `--logpath` parameter.
5. Replace both instances of `AWS_WAF_IP_SET_ID` in `/etc/fail2ban/action.d/aws-waf.conf` with the AWS WAF IP Sets ID that you would like to use.
6. Add `--global` flag if you work with global WAF (e.g. for Cloudfront)
7. Create or update your jail.local configuration. Replace the filter definition below with your own filter if you have one. The example filter configuration included in this package will match all POST and GET requests that are not images, css or javascript (note this doesn't include font files as of this time, but it probably should). The filter together with the jail.local configuration here will be useful for stopping crawl attempts and certain types of HTTP Flood DoS or brute force attacks. Here's an example jail.local configuration:
  
```
[aws-waf-example]
enabled  = true
port     = http,https
filter   = aws-waf-example-filter
logpath  = /var/log/nginx/*.access.*
findtime = 120
maxretry = 200
action = aws-waf[name=Example]
    sendmail-whois[name=LoginDetect, dest=youremail@example.com, sender=youremail@local.hostname, sendername="Fail2Ban"]
```
