FROM node:carbon

LABEL MAINTAINER="Subash SN"

WORKDIR /app

COPY . .

RUN sed -i 's/\r$//' /app/entrypoint.sh && \
    sed -i 's/\r$//' /app/wait-for-it.sh && \
    chmod +x /app/entrypoint.sh && \
    npm install

CMD ["bash", "/app/entrypoint.sh"]
