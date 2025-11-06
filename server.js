// backend/server.js

// Importa os pacotes necessários
const express = require('express');
const cors = require('cors');
const pool = require('./db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { autenticarToken, apenasTecnicos } = require('./authMiddleware');
const multer = require('multer');
const path = require('path');

// --- (Configuração do Multer) ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => { cb(null, 'uploads/'); },
  filename: (req, file, cb) => { cb(null, Date.now() + '-' + file.originalname); }
});
const upload = multer({ storage: storage });

// --- (Configuração do Express) ---
const app = express();
const PORT = 3000;

// CORS explícito
app.use(cors({
  origin: 'http://localhost:4200',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// ========================================================
// SOCKET.IO (tempo real)
// ========================================================
const http = require('http');
const { Server } = require('socket.io');

// Cria servidor HTTP e conecta o Express nele
const server = http.createServer(app);

// Configura Socket.IO
const io = new Server(server, {
  cors: {
    origin: 'http://localhost:4200',
    methods: ['GET', 'POST']
  }
});

// Armazena conexões por usuário (userId -> socketId)
const clientesConectados = new Map();

/**
 * O cliente (Angular) deve emitir após login:
 * socket.emit('registrarUsuario', userId);
 */
io.on('connection', (socket) => {
  console.log('✅ WebSocket conectado:', socket.id);

  socket.on('registrarUsuario', (userId) => {
    if (!userId) return;
    clientesConectados.set(Number(userId), socket.id);
    console.log(`🔗 userId ${userId} associado ao socket ${socket.id}`);
  });

  socket.on('disconnect', () => {
    for (const [userId, sockId] of clientesConectados.entries()) {
      if (sockId === socket.id) {
        clientesConectados.delete(userId);
        break;
      }
    }
    console.log('❌ WebSocket desconectado:', socket.id);
  });
});

// Helpers para emitir eventos
function enviarParaUsuario(userId, evento, dados) {
  const socketId = clientesConectados.get(Number(userId));
  if (socketId) {
    io.to(socketId).emit(evento, dados);
  }
}

async function enviarParaTecnicos(evento, dados) {
  try {
    const [rows] = await pool.query("SELECT id FROM perfis WHERE nivel IN ('tecnico','admin')");
    rows.forEach(r => enviarParaUsuario(r.id, evento, dados));
  } catch (e) {
    console.error('Erro ao emitir para técnicos:', e?.message || e);
  }
}

// ========================================================
// ROTAS DA API (VÊM PRIMEIRO)
// ========================================================

// GET /api/chamados (ATUALIZADO COM JOIN)
app.get('/api/chamados', autenticarToken, async (req, res) => {
  const usuario = req.usuario;
  const { status } = req.query;
  try {
    let sql;
    let params = [];
    let baseQuery = `
      SELECT 
        c.*, 
        p.nome_completo as solicitante_nome 
      FROM chamados c
      JOIN perfis p ON c.criado_por_id = p.id
    `;
    let conditions = [];

    if (!(usuario.nivel === 'tecnico' || usuario.nivel === 'admin')) {
      // Visão Funcionário: vê só os seus
      conditions.push('c.criado_por_id = ?');
      params.push(usuario.id);
    }

    if (status) {
      conditions.push('c.status = ?');
      params.push(status);
    }

    if (conditions.length > 0) {
      sql = baseQuery + ' WHERE ' + conditions.join(' AND ');
    } else {
      sql = baseQuery;
    }

    sql += ' ORDER BY c.criado_em DESC';

    const [rows] = await pool.query(sql, params);
    res.json(rows);
  } catch (err) {
    console.error('Erro ao buscar chamados:', err);
    res.status(500).json({ message: 'Erro ao buscar dados' });
  }
});

// GET /api/chamado/:id (liberado: funcionário só vê os dele)
app.get('/api/chamado/:id', autenticarToken, async (req, res) => {
  const chamadoId = req.params.id;
  const usuario = req.usuario;

  try {
    const sql = `
      SELECT 
        c.*, 
        p_solicitante.nome_completo as solicitante_nome,
        p_solicitante.setor_texto as solicitante_setor,
        p_solicitante.cargo_texto as solicitante_cargo,
        p_tecnico.nome_completo as tecnico_atribuido_nome 
      FROM chamados c
      JOIN perfis p_solicitante ON c.criado_por_id = p_solicitante.id
      LEFT JOIN perfis p_tecnico ON c.atribuido_para_id = p_tecnico.id
      WHERE c.id = ?
    `;
    const [rows] = await pool.query(sql, [chamadoId]);

    if (rows.length === 0) {
      return res.status(404).json({ message: 'Chamado não encontrado.' });
    }

    const chamado = rows[0];

    // Funcionário só pode ver chamado que ele criou
    if (usuario.nivel === 'funcionario' && chamado.criado_por_id !== usuario.id) {
      return res.status(403).json({ message: 'Acesso negado: este chamado não pertence a você.' });
    }

    res.json(chamado);
  } catch (err) {
    console.error('Erro ao buscar detalhe do chamado:', err);
    res.status(500).json({ message: 'Erro ao buscar dados' });
  }
});

// GET /api/tecnicos
app.get('/api/tecnicos', autenticarToken, apenasTecnicos, async (req, res) => {
  try {
    const sql = "SELECT id, nome_completo FROM perfis WHERE nivel = 'tecnico' OR nivel = 'admin' ORDER BY nome_completo";
    const [rows] = await pool.query(sql);
    res.json(rows);
  } catch (err) {
    console.error('Erro ao buscar técnicos:', err);
    res.status(500).json({ message: 'Erro ao buscar dados' });
  }
});

// POST /api/chamado (com upload) -> emite "novo-chamado" para técnicos
app.post('/api/chamado', autenticarToken, upload.single('anexo'), async (req, res) => {
  try {
    const { titulo, descricao } = req.body;
    const criado_por_id = req.usuario.id;
    let anexo_url = null;
    if (req.file) {
      anexo_url = `http://localhost:3000/uploads/${req.file.filename}`;
    }
    const sql = `
      INSERT INTO chamados (titulo, descricao, criado_por_id, anexo_url)
      VALUES (?, ?, ?, ?)
    `;
    const params = [titulo, descricao, criado_por_id, anexo_url];
    const [result] = await pool.query(sql, params);
    const [novoChamadoRows] = await pool.query('SELECT * FROM chamados WHERE id = ?', [result.insertId]);
    const novoChamado = novoChamadoRows[0];

    // ⚡ Tempo real: notifica todos técnicos
    await enviarParaTecnicos('novo-chamado', {
      id: novoChamado.id,
      titulo: novoChamado.titulo,
      criado_por_id,
      criado_em: novoChamado.criado_em,
      status: novoChamado.status
    });

    res.status(201).json(novoChamado);
  } catch (err) {
    console.error('Erro ao criar chamado:', err);
    res.status(500).json({ message: 'Erro ao salvar dados' });
  }
});

app.get('/api/chamados/:id/relatorio', autenticarToken, apenasTecnicos, async (req, res) => {
  const chamadoId = req.params.id;

  try {
    const sql = `
      SELECT r.id, r.titulo, r.relatorio, r.criado_em,
             p.nome_completo AS tecnico_nome
      FROM relatorios_chamado r
      LEFT JOIN perfis p ON p.id = r.tecnico_id
      WHERE r.chamado_id = ?
      ORDER BY r.criado_em DESC
      LIMIT 1
    `;
    const [rows] = await pool.query(sql, [chamadoId]);
    res.json(rows[0] || null);
  } catch (err) {
    console.error('Erro ao buscar relatório:', err);
    res.status(500).json({ message: 'Erro ao buscar relatório' });
  }
});

app.post('/api/chamados/:id/relatorio', autenticarToken, apenasTecnicos, async (req, res) => {
  const chamadoId = Number(req.params.id);
  const tecnicoId = req.usuario.id;
  const { titulo, relatorio } = req.body;

  if (!titulo || !titulo.trim() || !relatorio || !relatorio.trim()) {
    return res.status(400).json({ message: 'Título e relatório são obrigatórios.' });
  }

  try {
    // 1) Garantir que o chamado está FECHADO
    const [chRows] = await pool.query('SELECT status FROM chamados WHERE id = ?', [chamadoId]);
    if (!chRows.length) return res.status(404).json({ message: 'Chamado não encontrado.' });
    if (chRows[0].status !== 'fechado') {
      return res.status(400).json({ message: 'Só é possível registrar relatório com o chamado fechado.' });
    }

    // 2) Impedir duplicidade: um relatório por chamado
    const [relRows] = await pool.query('SELECT id FROM relatorios_chamado WHERE chamado_id = ? LIMIT 1', [chamadoId]);
    if (relRows.length) {
      return res.status(409).json({ message: 'Este chamado já possui relatório final.' });
    }

    // 3) Inserir
    const insertSql = `
      INSERT INTO relatorios_chamado (chamado_id, tecnico_id, titulo, relatorio)
      VALUES (?, ?, ?, ?)
    `;
    await pool.query(insertSql, [chamadoId, tecnicoId, titulo.trim(), relatorio.trim()]);

    // 4) Retornar o último relatório
    const [outRows] = await pool.query(
      `SELECT r.id, r.titulo, r.relatorio, r.criado_em, p.nome_completo AS tecnico_nome
       FROM relatorios_chamado r
       LEFT JOIN perfis p ON p.id = r.tecnico_id
       WHERE r.chamado_id = ?
       ORDER BY r.criado_em DESC
       LIMIT 1`,
      [chamadoId]
    );

    res.status(201).json(outRows[0]);
  } catch (err) {
    console.error('Erro ao salvar relatório:', err);
    res.status(500).json({ message: 'Erro ao salvar relatório' });
  }
});

// --- AÇÕES DE TÉCNICO (PUT) ---

// PUT /api/chamados/:id/atribuir -> emite "chamado-atribuido" para o técnico escolhido
app.put('/api/chamados/:id/atribuir', autenticarToken, apenasTecnicos, async (req, res) => {
  const chamadoId = req.params.id;
  const { tecnicoId } = req.body;

  if (!tecnicoId) {
    return res.status(400).json({ message: 'ID do técnico é obrigatório.' });
  }

  try {
    // 1) Atualiza banco
    await pool.query(
      `UPDATE chamados SET atribuido_para_id = ?, status = 'em_andamento' WHERE id = ?`,
      [tecnicoId, chamadoId]
    );

    // 2) Busca nomes envolvidos
    const [[ch]] = await pool.query(
      `SELECT c.criado_por_id, p.nome_completo AS tecnico_nome
       FROM chamados c
       JOIN perfis p ON p.id = ?
       WHERE c.id = ?`,
      [tecnicoId, chamadoId]
    );

    const tecnicoNome = ch.tecnico_nome;
    const criadorId = ch.criado_por_id;

    // 3) Notifica técnico
    enviarParaUsuario(tecnicoId, 'chamado-atribuido', {
      chamadoId: Number(chamadoId),
      tipo: 'atribuido',
      mensagem: `Você recebeu um novo chamado`,
      tecnicoNome
    });

    // ✅ 4) Notifica funcionário criador
    if (criadorId) {
      enviarParaUsuario(criadorId, 'chamado-atribuido', {
        chamadoId: Number(chamadoId),
        tipo: 'atribuido',
        mensagem: `Seu chamado foi atribuído ao técnico ${tecnicoNome}`,
        tecnicoNome
      });
    }

    res.json({ message: 'Chamado atribuído com sucesso!' });
  } catch (err) {
    console.error('Erro ao atribuir chamado:', err);
    res.status(500).json({ message: 'Erro ao salvar dados' });
  }
});

// PUT /api/chamados/:id/status -> emite "status-alterado" para criador e técnico
app.put('/api/chamados/:id/status', autenticarToken, apenasTecnicos, async (req, res) => {
  const chamadoId = req.params.id;
  const { novoStatus } = req.body;
  try {
    const sql = 'UPDATE chamados SET status = ? WHERE id = ?';
    await pool.query(sql, [novoStatus, chamadoId]);

    // Buscar envolvidos
    const [cRows] = await pool.query('SELECT criado_por_id, atribuido_para_id FROM chamados WHERE id = ?', [chamadoId]);
    const criadorId = cRows[0]?.criado_por_id;
    const tecnicoId = cRows[0]?.atribuido_para_id;

    const payload = { chamadoId: Number(chamadoId), status: String(novoStatus) };

    if (criadorId) enviarParaUsuario(criadorId, 'status-alterado', payload);
    if (tecnicoId) enviarParaUsuario(tecnicoId, 'status-alterado', payload);

    res.json({ message: 'Status atualizado com sucesso!' });
  } catch (err) {
    console.error('Erro ao mudar status:', err);
    res.status(500).json({ message: 'Erro ao salvar dados' });
  }
});

// PUT /api/chamados/:id/prioridade (sem notificação por enquanto)
app.put('/api/chamados/:id/prioridade', autenticarToken, apenasTecnicos, async (req, res) => {
  const chamadoId = req.params.id;
  const { novaPrioridade } = req.body;
  if (!novaPrioridade) {
    return res.status(400).json({ message: 'Nova prioridade é obrigatória.' });
  }
  try {
    const sql = 'UPDATE chamados SET prioridade = ? WHERE id = ?';
    await pool.query(sql, [novaPrioridade, chamadoId]);
    res.json({ message: 'Prioridade atualizada com sucesso!' });
  } catch (err) {
    console.error('Erro ao mudar prioridade:', err);
    res.status(500).json({ message: 'Erro ao salvar dados' });
  }
});

// --- ENDPOINTS DE AUTENTICAÇÃO ---
app.post('/api/register', async (req, res) => {
  const { email, pass, nomeCompleto, setor, cargo } = req.body;
  if (!email || !pass || !nomeCompleto || !setor || !cargo) {
    return res.status(400).json({ message: 'Todos os campos são obrigatórios.' });
  }
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const salt = await bcrypt.genSalt(10);
    const senhaHash = await bcrypt.hash(pass, salt);
    const [userResult] = await connection.query(
      'INSERT INTO usuarios (email, senha_hash) VALUES (?, ?)',
      [email, senhaHash]
    );
    const novoUsuarioId = userResult.insertId;
    await connection.query(
      'INSERT INTO perfis (id, nome_completo, setor_texto, cargo_texto) VALUES (?, ?, ?, ?)',
      [novoUsuarioId, nomeCompleto, setor, cargo]
    );
    await connection.commit();
    res.status(201).json({ message: 'Usuário criado com sucesso!', userId: novoUsuarioId });
  } catch (err) {
    await connection.rollback();
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ message: 'Este email já está cadastrado.' });
    }
    console.error('Erro ao registrar usuário:', err);
    res.status(500).json({ message: 'Erro interno no servidor.' });
  } finally {
    if (connection) {
      connection.release();
    }
  }
});

app.post('/api/login', async (req, res) => {
  const { email, pass } = req.body;

  if (!email || !pass) {
    return res.status(400).json({ message: 'Email e senha são obrigatórios.' });
  }

  try {
    const [rows] = await pool.query(
      `SELECT 
         u.id, 
         u.email, 
         u.senha_hash, 
         p.nome_completo,
         p.nivel, 
         p.setor_texto, 
         p.cargo_texto 
       FROM usuarios u
       JOIN perfis p ON u.id = p.id
       WHERE u.email = ?`,
      [email]
    );

    if (rows.length === 0) {
      return res.status(401).json({ message: 'Email ou senha inválidos.' });
    }

    const usuario = rows[0];
    const senhaCorreta = await bcrypt.compare(pass, usuario.senha_hash);
    if (!senhaCorreta) {
      return res.status(401).json({ message: 'Email ou senha inválidos.' });
    }

    const payload = {
      id: usuario.id,
      email: usuario.email,
      nome_completo: usuario.nome_completo,
      nivel: usuario.nivel,
      setor: usuario.setor_texto,
      cargo: usuario.cargo_texto
    };

    const token = jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({ message: 'Login bem-sucedido!', token });
  } catch (err) {
    console.error('Erro no login:', err);
    res.status(500).json({ message: 'Erro interno no servidor.' });
  }
});

// Comentários: listar
app.get('/api/chamados/:id/comentarios', autenticarToken, async (req, res) => {
  const chamadoId = req.params.id;

  try {
    const sql = `
      SELECT c.id, c.texto, c.criado_em, p.nome_completo AS autor, p.nivel AS autor_nivel
      FROM comentarios c
      JOIN perfis p ON c.usuario_id = p.id
      WHERE c.chamado_id = ?
      ORDER BY c.criado_em ASC
    `;
    const [rows] = await pool.query(sql, [chamadoId]);
    res.json(rows);
  } catch (err) {
    console.error('Erro ao buscar comentários:', err);
    res.status(500).json({ message: 'Erro ao buscar comentários' });
  }
});

// Comentários: criar -> emite "novo-comentario" para criador e técnico
app.post('/api/chamados/:id/comentarios', autenticarToken, async (req, res) => {
  const chamadoId = req.params.id;
  const usuarioId = req.usuario.id;
  const { texto } = req.body;

  if (!texto || texto.trim() === '') {
    return res.status(400).json({ message: 'O comentário não pode estar vazio.' });
  }

  try {
    const insertSql = `
      INSERT INTO comentarios (texto, chamado_id, usuario_id)
      VALUES (?, ?, ?)
    `;
    await pool.query(insertSql, [texto, chamadoId, usuarioId]);

    // Busca autor (nome + nível)
    const [autorRows] = await pool.query(
      'SELECT nome_completo AS autor, nivel AS autor_nivel FROM perfis WHERE id = ?',
      [usuarioId]
    );

    // Busca envolvidos do chamado
    const [cRows] = await pool.query(
      'SELECT criado_por_id, atribuido_para_id FROM chamados WHERE id = ?',
      [chamadoId]
    );
    const criadorId = cRows[0]?.criado_por_id;
    const tecnicoId = cRows[0]?.atribuido_para_id;

    const payload = {
      chamadoId: Number(chamadoId),
      texto,
      autor: autorRows[0]?.autor || 'Usuário',
      autor_nivel: autorRows[0]?.autor_nivel || 'funcionario',
      criado_em: new Date()
    };

    // ⚡ Tempo real: notifica criador e técnico (bidirecional)
    if (criadorId) enviarParaUsuario(criadorId, 'novo-comentario', payload);
    if (tecnicoId) enviarParaUsuario(tecnicoId, 'novo-comentario', payload);

    res.status(201).json({ message: 'Comentário adicionado com sucesso!' });
  } catch (err) {
    console.error('🔥 ERRO AO INSERIR COMENTÁRIO:', err.code, err.sqlMessage);
    res.status(500).json({ message: 'Erro ao salvar comentário' });
  }
});

// --- ROTA CATCH-ALL (DEVE SER A ÚLTIMA ROTA!) ---
// Redireciona todas as outras requisições (ex: /dashboard, /login) para o index.html do Angular.
app.use((req, res) => {
  const indexPath = path.join(__dirname, 'public/index.html');
  res.sendFile(indexPath, (err) => {
    if (err) {
      console.error('Erro ao servir index.html:', err);
      res.status(500).send(err);
    }
  });
});

// --- INICIAR SERVIDOR (com WebSockets) ---
server.listen(PORT, () => {
  console.log(`🚀 Servidor Node.js + WebSockets rodando em http://localhost:${PORT}`);
});
