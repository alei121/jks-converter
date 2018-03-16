FROM openjdk:8-jre-alpine
MAINTAINER Alan Lei <alanlei+docker@gmail.com>
RUN apk add --no-cache python3 openssl
COPY ./webapp/requirements.txt /tmp/requirements.txt
RUN pip3 install -qr /tmp/requirements.txt
RUN mkdir -p /opt/webapp
COPY ./webapp /opt/webapp/
WORKDIR /opt/webapp
EXPOSE 80
CMD ["python3", "app.py"]

