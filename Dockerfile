FROM ubuntu:18.04

MAINTAINER Ondrej Borysek "bakalarka@borysek.net"

RUN apt-get update -y && \
    apt-get install -y python3.7 python3.7-dev python3-pip git openssh-server cron

# Invalidate cache from this point onwards when integration branch HEAD changes.
ADD https://api.github.com/repos/BorysekOndrej/bakalarka3/git/refs/heads/integration branch_version.json

RUN git clone https://github.com/BorysekOndrej/bakalarka3.git /app/bakalarka3

WORKDIR /app/bakalarka3

RUN git checkout integration
RUN mkdir db tmp log
RUN python3.7 -m pip install -r requirements.txt

# Add cron for the most basic of automatic triggering.
COPY crontab /etc/cron.d/tlsinventory
RUN chmod 0744 /etc/cron.d/tlsinventory
RUN crontab /etc/cron.d/tlsinventory


# https://stackoverflow.com/a/39278224
# The following is used to invalidate caching when branch changes and then only doing changes.
# ADD https://api.github.com/repos/BorysekOndrej/bakalarka3/git/refs/heads/integration branch_version.json
# RUN git checkout integration && git pull
# RUN python3.7 -m pip install -r requirements.txt

ENTRYPOINT [ "python3.7", "start.py" ]
# 
# CMD [ "app.py" ]
