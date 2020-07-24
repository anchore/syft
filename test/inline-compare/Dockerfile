FROM python:3

WORKDIR /
COPY syft-reports /syft-reports
COPY inline-reports /inline-reports
COPY compare.py .
ENTRYPOINT ["/compare.py"]