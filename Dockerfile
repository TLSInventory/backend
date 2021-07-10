FROM ubuntu:18.04

LABEL maintainer="tlsinventory@borysek.net" 

RUN apt-get update -y && \
    apt-get install -y python3.7 python3.7-dev python3-pip git openssh-server cron nano

WORKDIR /app/tlsinventory-backend

COPY ./ .

# RUN git checkout master
RUN mkdir -p db tmp log
RUN python3.7 -m pip install -r requirements.txt

# Add cron for the most basic of automatic triggering.
COPY crontab /etc/cron.d/tlsinventory
RUN chmod 0744 /etc/cron.d/tlsinventory
RUN crontab /etc/cron.d/tlsinventory


ENTRYPOINT [ "/bin/sh", "-c", "cron && /app/tlsinventory-backend/start.sh" ]
