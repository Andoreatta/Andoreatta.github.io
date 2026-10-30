+++
title = 'Web Technologies'
date = 2026-10-30
type = 'notes'
weight = 40
toc = false
tags = ['web', 'web-technologies']
description = 'Tomcat, IIS, WordPress, Drupal, Joomla, GitLab, Jenkins, WebSphere, SAP NetWeaver, CGI and PDF generators: fingerprinting, default paths, and the exploits that actually land.'
+++

## **Identifying Web Technologies**

> The first step to perform a web application penetration test is to identify the target's web technology in use. In order to do that, you can follow these basic steps:

1. Peform nmap scans against the target web application's open port
2. Analyze the web application:
   * Using [Wappalyzer](https://www.wappalyzer.com/) as a browser extension
   * Using `whatweb http://server.com --log-verbose output-file`
3. Look for the following generic files: `robots.txt`, `sitemap.xml`, `README.txt`, `CHANGELOG.txt`
4. Analyze the website's footer, header and source code to check for references to the web technology used
5. Analyze the HTTP Response Headers
6. Force errors to trigger unexpected behaviors in the web application that may cause information disclosure

***

## **External Resources**

* [https://book.hacktricks.xyz/network-services-pentesting/pentesting-web#web-tech-tricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web#web-tech-tricks)
