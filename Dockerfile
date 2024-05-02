FROM node
WORKDIR /app
RUN git clone https://github.com/Lyall-A/HTTP-Reverse-Proxy .
COPY . .
CMD ["node", "."]
