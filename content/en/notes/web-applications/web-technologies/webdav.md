+++
title = 'WebDav'
date = 2026-10-30
type = 'notes'
weight = 60
toc = true
tags = ['web', 'web-technologies', 'webdav', 'iis']
+++

WebDAV (Web Distributed Authoring and Versioning) is a **protocol** that extends the HTTP protocol, allowing users to **collaboratively author and manage files** on a web server, enabling actions like creating, editing, moving, and deleting files remotely.

An HTTP Server with WebDav **might require valid credentials** to perform file operations, such as creating, deleting or editing existing files. The credentials are most probably required via **HTTP Basic Authentication**.

{{< hint success >}}
**Notice: You will need to use the HTTP PUT, DELETE and MOVE verbs to respectively upload, delete and move files.**
{{< /hint >}}

{{< hint warning >}}
**Sometimes, the WebDav instance might be configured to deny any file upload using specific file extensions. If this configuration is not properly set, you might be able to subvert it by uploading the file with any other accepted extension, and then using a move (rename) operation or a copy operation.**
{{< /hint >}}

***

## IIS5/6 WebDav Extension Bypass

In this specific setting, the WebDav instance won't allow uploading or renaming files with the `.asp` extension, but you can bypass this restriction by uploading a file as a `.txt` file and copy/move it to a `.asp;.txt` file. (Notice the `;`"is required, as it is the means for the bypass to work)

***

## Useful Tools

[DavTest](https://github.com/cldrn/davtest): An _automated_ tool to perform several checks over the WebDav server

```bash
davtest -url http://<IP>
```

Be careful when using DavTest, as <mark>**its default configuration is to upload files**</mark> on the dav server!

***

[Cadaver](https://github.com/notroj/cadaver): A tool to connect to the WebDav server via CLI and perform standard WebDav actions _manually_

```bash
cadaver <IP>
```

***

## Finding Credentials inside an Apache Server

If the Webdav was using an Apache server which you have access to, you should look at configured sites in Apache.
 You can find these credentials inside the following file:
\
`/etc/apache2/sites-enabled/000-default`
