# Update CSRF Token
This Burp extension is used to update CSRF tokens, similar to how Burp's cooke jar works. It parses the CSRF token from the set-cookie in HTTP response and update it in the header of the subsequent HTTP requests.

## Example
It will extract the following CSRF token from an HTTP response:
```
Set-Cookie: XSRF-TOKEN=db2c9c65-ea48-4452-a81a-0c98c9a6667e; Path=/
```

And then include it in future request headers in the following format:
```
X-XSRF-TOKEN: db2c9c65-ea48-4452-a81a-0c98c9a6667e
```

