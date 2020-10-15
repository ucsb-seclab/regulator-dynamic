FROM node:14.13

WORKDIR /opt/regulator/gather_samples

ADD package.json package.json

ADD package-lock.json package-lock.json

RUN npm install

ADD index.js index.js

ENTRYPOINT [ "node", "index.js" ]

