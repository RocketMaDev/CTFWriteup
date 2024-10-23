FROM ubuntu@sha256:77d57fd89366f7d16615794a5b53e124d742404e20f035c22032233f1826bd6a

RUN sed -i 's@//.*archive.ubuntu.com@//mirrors.ustc.edu.cn@g' /etc/apt/sources.list.d/ubuntu.sources && \
    sed -i 's/security.ubuntu.com/mirrors.ustc.edu.cn/g'      /etc/apt/sources.list.d/ubuntu.sources
RUN apt update && apt upgrade -y && \
    apt install libseccomp2 google-perftools binutils xinetd -y 
RUN useradd ctf -u 1001 -s /bin/bash -m

WORKDIR /home/ctf
COPY ./ChromeLogger.orig ChromeLogger
COPY ./checkdeps.sh checkdeps.sh
COPY ./lib lib
COPY ./start.sh start.sh
COPY ./ctf.xinetd /etc/xinetd.d/ctf

RUN chmod 744 checkdeps.sh start.sh && \
    chmod 755 ChromeLogger
RUN ./checkdeps.sh

EXPOSE 1337

CMD ["./start.sh"]
