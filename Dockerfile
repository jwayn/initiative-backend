FROM node:8-alpine
WORKDIR /app
COPY package.json /app
RUN yarn install
COPY . /app
CMD ["yarn", "start"]