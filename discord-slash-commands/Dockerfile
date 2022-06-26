FROM public.ecr.aws/lambda/nodejs:14

COPY app.js package.json .env ./
COPY modules ./modules
COPY node_modules ./node_modules

RUN npm install

CMD ["app.lambdaHandler"]
