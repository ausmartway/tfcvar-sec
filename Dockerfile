FROM alpine
# RUN apk update && apk add \
# bash \
# curl
# RUN curl -L https://raw.githubusercontent.com/ausmartway/tfcvar-sec/main/install.sh | bash
COPY tfcvar-sec /usr/bin/tfcvar-sec
ENTRYPOINT [ "tfcvar-sec" ]
CMD ["-v"]