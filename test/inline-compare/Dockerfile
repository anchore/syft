FROM python:3

WORKDIR /
COPY imgbom-reports /imgbom-reports
COPY inline-reports /inline-reports
COPY compare.py .
ENTRYPOINT ["/compare.py"]