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

// --- AQUI ESTÁ A CORREÇÃO ---
// Configuração de CORS mais explícita para lidar com pre-flight (OPTIONS)
// Isto substitui o app.use(cors()) simples.
app.use(cors({
  origin: 'http://localhost:4200', // Permite APENAS o seu Angular
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // Permite estes métodos
  allowedHeaders: ['Content-Type', 'Authorization'] // Permite estes headers
}));

app.use(express.json()); 
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));


// --- ROTAS DA API (VÊM PRIMEIRO) ---

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
    if (usuario.nivel === 'tecnico' || usuario.nivel === 'admin') {
      // Visão TI
    } else {
      // Visão Funcionário
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
    console.log(`Executando SQL: ${sql.replace(/\s+/g, ' ')} com parâmetros: [${params.join(', ')}]`);
    const [rows] = await pool.query(sql, params);
    console.log(`Query executada, ${rows.length} chamados encontrados (Filtro: ${status || 'nenhum'}).`);
    res.json(rows);
  } catch (err) {
    console.error('Erro ao buscar chamados:', err);
    res.status(500).json({ message: 'Erro ao buscar dados' });
  }
});

// GET /api/chamado/:id
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

    // ✅ Funcionário só pode ver chamado que ele criou
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
  console.log('Recebida requisição para GET /api/tecnicos'); 
  try {
    const sql = "SELECT id, nome_completo FROM perfis WHERE nivel = 'tecnico' OR nivel = 'admin' ORDER BY nome_completo";
    const [rows] = await pool.query(sql);
    console.log(`Encontrados ${rows.length} técnicos.`); 
    res.json(rows);
  } catch (err) {
    console.error('Erro ao buscar técnicos:', err);
    res.status(500).json({ message: 'Erro ao buscar dados' });
  }
});

// POST /api/chamado (com upload)
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
    res.status(201).json(novoChamadoRows[0]);
  } catch (err) {
    console.error('Erro ao criar chamado:', err);
    res.status(500).json({ message: 'Erro ao salvar dados' });
  }
});

// --- AÇÕES DE TÉCNICO (PUT) ---
app.put('/api/chamados/:id/atribuir', autenticarToken, apenasTecnicos, async (req, res) => {
  const chamadoId = req.params.id;
  const { tecnicoId } = req.body; 
  if (!tecnicoId) {
    return res.status(400).json({ message: 'ID do técnico é obrigatório.' });
  }
  try {
    const sql = `
      UPDATE chamados 
      SET atribuido_para_id = ?, status = 'em_andamento'
      WHERE id = ?
    `;
    await pool.query(sql, [tecnicoId, chamadoId]);
    res.json({ message: 'Chamado atribuído com sucesso!' });
  } catch (err) {
    console.error('Erro ao atribuir chamado:', err);
    res.status(500).json({ message: 'Erro ao salvar dados' });
  }
});

app.put('/api/chamados/:id/status', autenticarToken, apenasTecnicos, async (req, res) => {
  const chamadoId = req.params.id;
  const { novoStatus } = req.body;
  try {
    const sql = 'UPDATE chamados SET status = ? WHERE id = ?';
    await pool.query(sql, [novoStatus, chamadoId]);
    res.json({ message: 'Status atualizado com sucesso!' });
  } catch (err) {
    console.error('Erro ao mudar status:', err);
    res.status(500).json({ message: 'Erro ao salvar dados' });
  }
});

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

    // ✅ Agora o token inclui nome_completo
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

app.post('/api/chamados/:id/comentarios', autenticarToken, async (req, res) => {
  const chamadoId = req.params.id;
  const usuarioId = req.usuario.id;
  const { texto } = req.body;

  if (!texto || texto.trim() === '') {
    return res.status(400).json({ message: 'O comentário não pode estar vazio.' });
  }

  try {
    const sql = `
      INSERT INTO comentarios (texto, chamado_id, usuario_id)
      VALUES (?, ?, ?)
    `;
    await pool.query(sql, [texto, chamadoId, usuarioId]);
    res.status(201).json({ message: 'Comentário adicionado com sucesso!' });
  } catch (err) {
    console.error('🔥 ERRO AO INSERIR COMENTÁRIO:', err.code, err.sqlMessage);
    res.status(500).json({ message: 'Erro ao salvar comentário' });
  }
});


// --- ROTA CATCH-ALL (DEVE SER A ÚLTIMA ROTA!) ---
// Redireciona todas as outras requisições (ex: /dashboard, /login)
// para o index.html do Angular.
app.use((req, res) => {
  const indexPath = path.join(__dirname, 'public/index.html');
  res.sendFile(indexPath, (err) => {
    if (err) {
      console.error('Erro ao servir index.html:', err);
      res.status(500).send(err);
    }
  });
});

// Liga o servidor
app.listen(PORT, () => {
  console.log(`Servidor Node.js (com MySQL) rodando em http://localhost:${PORT}`);
});