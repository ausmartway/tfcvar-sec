FROM alpine
RUN apk update
RUN apk add bash
RUN apk add curl
RUN curl -L https://raw.githubusercontent.com/ausmartway/tfcvar-sec/main/install.sh | bash
CMD ["tfcvar-sec", "scan"]

