FROM centos:7.9.2009
# modifying the RPM DB multiple times will result in duplicate packages when using all-layers (if there was no de-dup logic)
# curl is tricky, it already exists in the image and is being upgraded
RUN yum install -y wget-1.14-18.el7_6.1 curl-7.29.0-59.el7_9.1
RUN yum install -y vsftpd-3.0.2-29.el7_9
RUN yum install -y httpd-2.4.6-97.el7.centos.5