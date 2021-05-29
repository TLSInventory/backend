FROM ubuntu:18.04

LABEL maintainer="tlsinventory@borysek.net" 

RUN apt-get update -y && \
    apt-get install -y python3.7 python3.7-dev python3-pip git openssh-server cron

# Todo: this docker makes the container from github master, not from local. Change that.

# Invalidate cache from this point onwards when master branch HEAD changes.
ADD https://api.github.com/repos/TLSInventory/backend/git/refs/heads/master branch_version.json

RUN git clone https://github.com/TLSInventory/backend.git /app/tlsinventory-backend

WORKDIR /app/tlsinventory-backend

RUN git checkout master
RUN mkdir db tmp log
RUN python3.7 -m pip install -r requirements.txt

# Add cron for the most basic of automatic triggering.
COPY crontab /etc/cron.d/tlsinventory
RUN chmod 0744 /etc/cron.d/tlsinventory
RUN crontab /etc/cron.d/tlsinventory


ENTRYPOINT [ "python3.7", "start.py" ]
# 
# CMD [ "app.py" ]
