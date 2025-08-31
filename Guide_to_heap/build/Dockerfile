FROM ubuntu@sha256:a08e551cb33850e4740772b38217fc1796a66da2506d312abe51acda354ff061dfbffa AS base
WORKDIR /app
COPY --chmod=555 chall run
RUN echo "fwectf{kn0w1ng_7c4ch3}" > /flag.txt
RUN mv /flag.txt /flag-$(md5sum /flag.txt | awk '{print $1}').txt

FROM pwn.red/jail
COPY --from=base / /srv
ENV JAIL_TIME=120 JAIL_CPU=100 JAIL_MEM=10M
