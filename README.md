# ssl-peeker

Checks a host for SSL info, like who the certificate was issued to, who it was issued by, when it's valid, what protocols are enabled, and what ciphers are available.  Basically just a simple GUI for parts of [sslinfo](https://github.com/iamthechad/sslinfo).

### Installation

```
npm install -g ssl-peeker
```

### Usage

```
ssl-peeker <host> [port]
```

**host** is required.  This is either the hostname or IP address whose SSL info you want to peek at.

**port** is optional.  By default, HTTP/S runs on port 443, but in case that's not true for you, you can specify the port as well.
