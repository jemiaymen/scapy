FROM python:3.8.10
RUN pip install scapy==2.4.0

CMD [ "scapy" ]