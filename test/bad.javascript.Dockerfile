FROM node:12-alpine

WORKDIR /home

RUN npm init -y
RUN npm install cross-env \
    eslint \
    eslint-config-godaddy-react \
    eslint-plugin-mocha \
    eslint-plugin-react-hooks \
    path-parse
