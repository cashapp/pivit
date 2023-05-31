FROM alpine:3.15

RUN apk update
RUN apk add --no-cache bash
RUN apk add git
RUN apk add jq
RUN apk add openssh
RUN wget https://github.com/cli/cli/releases/download/v2.29.0/gh_2.29.0_linux_amd64.tar.gz
RUN tar -zxvf gh_2.29.0_linux_amd64.tar.gz
ENV PATH=$PATH:/gh_2.29.0_linux_amd64/bin

COPY src/* /

ENTRYPOINT ["/check.sh"]