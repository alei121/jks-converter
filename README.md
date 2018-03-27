# jks-converter

This docker image runs a webapp that converts pem and key files into jks files.

For example, start container with this:
```
  docker run -p 5000:80 alei121/jks-convert
```
Then access from a browser with url localhost:5000

To convert pem/key to jks files:
1. Drag all relevant pem and key files into the dropbox
2. Enter password for the key file
3. Click Download

And the tool will:
- find the key cert chain and generate a keycert.jks
- create a trust.jks for all certs
- return a zip file with the two jks files

The docker image is based on openjdk:8-jre-alpine for the utility "keytool" to create jks.
It installs python3 and Flask for the webapp, and openssl to handle key files.

