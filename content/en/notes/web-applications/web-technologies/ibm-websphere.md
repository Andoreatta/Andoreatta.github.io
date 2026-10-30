+++
title = 'IBM WebSphere'
date = 2026-10-30
type = 'notes'
weight = 70
toc = true
tags = ['web', 'web-technologies', 'websphere', 'java']
+++

WebSphere is a Java EE application server provided by IBM, used to deploy and manage enterprise-level Java applications.

## Discovery & Fuzzing

Fuzz for IBM WebSphere specific endpoints using this wordlist: [https://github.com/kkrypt0nn/wordlists/blob/main/wordlists/vulnerabilities/websphere.txt](https://github.com/kkrypt0nn/wordlists/blob/main/wordlists/vulnerabilities/websphere.txt)

Fuzz for files with the following extensions:\
`*.do`
 `*.jsp` `*.jsv`
 `*.jsw`

***

## Missing Authorization in administrative servlets

You may find some interesting administrative endpoints lacking authentication.\
One particular endpoint is the `snoop` servlet, typically located at the server's webroot: `https://example.com/snoop/`

{{< hint info >}}
IBM WebSphere contains several default servlets. Check them out here:\
[https://www.ibm.com/docs/en/was/8.5.5?topic=applications-default-application](https://www.ibm.com/docs/en/was/8.5.5?topic=applications-default-application)
{{< /hint >}}

_`snoop`_ is a diagnostic servlet that displays detailed information about incoming HTTP requests, including headers, parameters, session attributes, and environment details.

It’s intended for **debugging** and administration, and should not be exposed in production environments due to the amount of internal data it reveals.

***

### HTTPOnly cookie Theft via snoop (requires XSS) 

While uncommon, you may find that the `snoop` servlet lacks authentication. In that case, you can chain it with an XSS vulnerability (if present) to gain access to any user's session cookies. 

In particular, the `snoop` endpoint prints back the request's headers, i**ncluding cookies with HTTPOnly set**, just like an `HTTP TRACE` request.

By leveraging this mechanism, you can read the user's session cookie inside the snoop response body and access the web application with it.
