FROM python:3-alpine

COPY requirements.txt /

RUN apk add --no-cache libcurl

RUN apk add --no-cache --virtual .build-dependencies build-base curl-dev \
 && pip install -r requirements.txt  \
 && apk del .build-dependencies build-base curl-dev

COPY cull-idle-servers.py /usr/local/bin/

USER nobody

ENTRYPOINT ["/usr/local/bin/cull-idle-servers.py"]
