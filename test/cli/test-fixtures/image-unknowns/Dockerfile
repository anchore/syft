FROM alpine@sha256:c5c5fda71656f28e49ac9c5416b3643eaa6a108a8093151d6d1afc9463be8e33
RUN rm -rf /lib/apk/db/installed
COPY . /home/files
# add a circular reference that will result in a failure while executing FindByGlob:
RUN mkdir -p /etc/alternatives && ln -s /etc/alternatives/java2 /etc/alternatives/java && ln -s /etc/alternatives/java /etc/alternatives/java2
