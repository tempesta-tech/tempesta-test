FROM python:3.10-alpine
ENV LOGLEVEL INFO
WORKDIR /run
COPY . .
RUN python3 -m pip install -r requirements.txt
ENTRYPOINT ["python3"]
CMD [""]
HEALTHCHECK --interval=0.5s --timeout=1s --retries=10 CMD \
            test -f /healthy || \
            nc -zv 127.0.0.1 8000 && touch /healthy
