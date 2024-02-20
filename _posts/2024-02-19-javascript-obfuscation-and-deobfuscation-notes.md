---
layout: post
title: Javascript Obfuscation and Deobfuscation Notes
date: 2024-02-19 18:10 +0000
---

## Obfuscation

There are many tools to obfuscate the code online:

- https://jsfuck.com/
- https://utf-8.jp/public/jjencode.html
- https://utf-8.jp/public/aaencode.html
- https://obfuscator.io/#code

To run the javascript code we can use the tool: `https://jsconsole.com/`


In addition to obfuscation another technique is used complementing the obfuscation called minify. Minify is essentially a method to reduce the javascript code into a single line. We can do it online with: `https://www.toptal.com/developers/javascript-minifier` 

## Deobfuscation

The reverse method of minify is whats called beautify. Beautify is a method used to ident the code in order to help in reading it. There are tools online that can accomplish that:
- https://beautifier.io/
- https://prettier.io/playground/

To deobfuscate the code we can use the tool: `https://matthewfl.com/unPacker.html`. However when the obfuscation tool is a custom one we need to reverse engineer the code because automatically tools might not work.


## Encoding and Decoding

### Base64

```shell
echo https://www.hackthebox.eu/ | base64
```

```shell
echo aHR0cHM6Ly93d3cuaGFja3RoZWJveC5ldS8K | base64 -d
```
### Hex

```shell
echo https://www.hackthebox.eu/ | xxd -p
```

```shell
echo 68747470733a2f2f7777772e6861636b746865626f782e65752f0a | xxd -p -r
```

### Rot13

```shell
echo https://www.hackthebox.eu/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

```shell
echo uggcf://jjj.unpxgurobk.rh/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

Tool to identify the encoding: `https://www.boxentriq.com/code-breaking/cipher-identifier`
Tool to help you decode: `https://gchq.github.io/CyberChef/`