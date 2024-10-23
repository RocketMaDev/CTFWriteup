FROM ubuntu:latest

RUN sed -i 's/archive.ubuntu.com/mirror.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list.d/ubuntu.sources && \
    sed -i 's/security.ubuntu.com/mirror.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list.d/ubuntu.sources
RUN apt-get update && apt-get -y dist-upgrade && \
    apt-get install -y debuginfod
RUN useradd ctf -s /bin/sh

WORKDIR /home/ctf

RUN if ! [ -d /usr/src ]; then mkdir -p /usr/src; fi

COPY ./source /usr/src/sauce
RUN chmod 0666 /usr/src/sauce/liquid.c
RUN mkdir service
COPY ./debuginfo /home/ctf/service
COPY ./start.sh .

EXPOSE 8002

CMD ["./start.sh"]
