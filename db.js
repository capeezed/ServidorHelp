// Importa os pacotes necessários
const mysql = require('mysql2/promise');
require('dotenv').config(); // Carrega as variáveis do arquivo .env

let pool;

try {
  // --- CONEXÃO COM O BANCO DE DADOS MYSQL ---
  // Cria um "pool" de conexões usando os dados do seu .env
  pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });

  console.log('Pool de conexões MySQL criado com sucesso!');
  
} catch (err) {
  console.error('ERRO AO CRIAR O POOL DO MYSQL:', err.message);
  console.log('Verifique se o MySQL está rodando e se o arquivo .env está correto.');
}

// Exporta o pool para que o server.js (e outros arquivos) possam usá-lo
module.exports = pool;