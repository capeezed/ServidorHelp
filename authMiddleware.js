// backend/authMiddleware.js
const jwt = require('jsonwebtoken');

/**
 * Middleware de Autenticação
 * Verifica o token JWT.
 */
function autenticarToken(req, res, next) {
  // Pega o token do header 'Authorization' (ex: "Bearer <token>")
  // A LINHA DO ERRO ESTÁ AQUI:
  // A variável 'authHeader' TEM de ser definida ANTES de ser usada.
  const authHeader = req.headers['authorization'];
  
  // A linha abaixo (provavelmente a sua linha 7) usa a variável
  const token = authHeader && authHeader.split(' ')[1]; // Pega só o token

  if (token == null) {
    return res.status(401).json({ message: 'Acesso negado: token não fornecido.' }); // 401 Unauthorized
  }

  // Verifica se o token é válido
  jwt.verify(token, process.env.JWT_SECRET, (err, usuarioPayload) => {
    if (err) {
      console.error('Erro ao verificar token:', err.message);
      return res.status(403).json({ message: 'Acesso negado: token inválido.' }); // 403 Forbidden
    }

    // Se o token for válido, ANEXA o payload (com id, email, nivel)
    // ao objeto 'req' para que as próximas rotas possam usá-lo.
    req.usuario = usuarioPayload;
    next(); // Continua para a próxima rota
  });
}

/**
 * Middleware de Autorização (Nível)
 * Verifica se o usuário é um técnico ou admin.
 * DEVE ser usado DEPOIS do 'autenticarToken'.
 */
function apenasTecnicos(req, res, next) {
  // O 'req.usuario' foi anexado pelo middleware 'autenticarToken'
  if (req.usuario && (req.usuario.nivel === 'tecnico' || req.usuario.nivel === 'admin')) {
    next(); // O usuário é um técnico, pode continuar
  } else {
    // O usuário é um 'funcionario', acesso negado
    return res.status(403).json({ message: 'Acesso negado: rota apenas para técnicos.' });
  }
}

module.exports = {
  autenticarToken,
  apenasTecnicos
};