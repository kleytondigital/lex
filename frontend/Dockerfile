# Etapa 1: Construção do projeto
FROM node:23-alpine AS build

WORKDIR /app

# Copia apenas os arquivos essenciais para instalar dependências
COPY package*.json ./
RUN npm install --frozen-lockfile

# Copia o restante dos arquivos e faz o build
COPY . .
RUN npm run build

# Etapa 2: Servindo com Vite Preview
FROM node:23-alpine AS runner

WORKDIR /app

# Copia apenas os arquivos de build para o container final
COPY --from=build /app/dist ./dist
COPY --from=build /app/package*.json ./

# Instala apenas as dependências necessárias para rodar o preview
RUN npm install

# Define as variáveis de ambiente do Vite
ENV VITE_API_URL=http://lex.aoseudispor.com.br:5000/api
ENV VITE_SITE_URL=http://lex.aoseudispor.com.br:3001
ENV VITE_SITE_CLIENTE_URL=http://lex.aoseudispor.com.br:3001/p
ENV VITE_SITE_CONSULTANT_URL=http://lex.aoseudispor.com.br:3001/c

EXPOSE 3001

# Comando para rodar o Vite Preview
CMD ["npm", "run", "preview", "--", "--host"]
