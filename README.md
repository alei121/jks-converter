# jks-converter

This docker image runs a webapp that converts pem and key files into jks files.

Drag all relevant pem and key files into the dropbox and the tool will:
- find the key cert chain and generate a keycert.jks
- create a trust.jks for all certs
- return a zip file with the two jks files

The docker image is based on openjdk:8-jre-alpine for the utility "keytool" to create jks.
It installs python3 and Flask for the webapp, and openssl to handle key files.

