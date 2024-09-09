# digest is for linux/amd64
FROM ubuntu:20.04@sha256:cc9cc8169c9517ae035cf293b15f06922cb8c6c864d625a72b7b18667f264b70 AS base

# install Python 3.8 and Python 3.9
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y python3.8 python3.9 python3-pip python3-venv python3.9-venv python3.8-venv

# install pip and virtualenv for both Python versions
RUN python3.8 -m pip install --upgrade pip virtualenv
RUN python3.9 -m pip install --upgrade pip virtualenv

# install global packages for Python 3.8 & 3.9
RUN python3.9 -m pip install click==8.0.3 beautifulsoup4==4.9.3 soupsieve==2.2.1 requests==2.25.1
RUN python3.9 -m pip install six==1.16.0 wcwidth==0.2.13 blessed==1.20.0 python-editor==1.0.4  # total dependencies for inquirer in project1 (which is linked)
RUN python3.9 -m pip install requests==2.25.0 certifi==2020.12.5 chardet==3.0.4 idna==2.10 urllib3==1.26.18 # total dependencies for requests

RUN python3.8 -m pip install click==8.0.2 beautifulsoup4==4.9.2 soupsieve==2.2.0 requests==2.25.0
RUN python3.8 -m pip install runs==1.2.2 xmod==1.8.1 # partial dependencies for inquirer in project2 (which is a red herring)
RUN python3.8 -m pip install requests==2.25.0 certifi==2020.12.5 chardet==3.0.4 idna==2.10 urllib3==1.26.18 # total dependencies for requests
RUN python3.8 -m pip install readchar==4.2.0

# create directories for the two projects
RUN mkdir -p /app/project1 /app/project2

# set up the first project with a virtual environment using Python 3.9
WORKDIR /app/project1
RUN python3.9 -m venv --system-site-packages venv
RUN /app/project1/venv/bin/pip install pyyaml==5.4.1 beautifulsoup4==4.10.0 soupsieve==2.3.0 requests # note: use requests from global site packages, but use the rest from the virtual environment
RUN /app/project1/venv/bin/pip install inquirer==3.0.0 # note: should use dependencies from global site packages

# set up the second project with a virtual environment using Python 3.8
WORKDIR /app/project2
RUN python3.8 -m venv venv
RUN /app/project2/venv/bin/pip install click==8.0.3 pyyaml==6.0
RUN /app/project2/venv/bin/pip install inquirer==3.2.4 runs==1.2.2 xmod==1.8.1 six==1.16.0 wcwidth==0.2.13 blessed==1.20.0 editor==1.6.6 readchar==4.1.0

WORKDIR /app

# let's not waste disk space... we only need the above state we've setup, not all of the os-level packages
RUN rm -rf /app/project1/venv/share
RUN rm -rf /app/project2/venv/share
RUN find /app/project1/venv/lib/python3.9/site-packages/* -type d ! -name '*.dist-info' -exec rm -rf {} +
RUN find /app/project2/venv/lib/python3.8/site-packages/* -type d ! -name '*.dist-info' -exec rm -rf {} +
RUN find /usr/local/lib/python3.8/dist-packages/* -type d ! -name '*.dist-info' -exec rm -rf {} +
RUN find /usr/local/lib/python3.9/dist-packages/* -type d ! -name '*.dist-info' -exec rm -rf {} +

FROM scratch

COPY --from=base /app/ /app/
COPY --from=base /usr/local/lib/python3.8/ /usr/local/lib/python3.8/
COPY --from=base /usr/local/lib/python3.9/ /usr/local/lib/python3.9/
