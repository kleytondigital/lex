FROM node:18-alpine

WORKDIR /app

# Instalar dependências necessárias para bcrypt
RUN apk add --no-cache python3 make g++

# Copiar arquivos de dependências
COPY package*.json ./

# Instalar dependências
RUN npm install

# Copiar código fonte
COPY . .

# Configurar variáveis de ambiente
ENV PORT=5000
ENV FRONTEND_URL=http://lex.aoseudispor.com.br:3001
ENV NODE_ENV=production
ENV JWT_SECRET=your_jwt_secret_here

EXPOSE 5000

CMD ["npm", "start"] 