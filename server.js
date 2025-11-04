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

// --- (Configuração do Multer e Express) ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => { cb(null, 'uploads/'); },
  filename: (req, file, cb) => { cb(null, Date.now() + '-' + file.originalname); }
});
const upload = multer({ storage: storage });
const app = express();
const PORT = 3000;
app.use(cors()); 
app.use(express.json()); 
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// --- API ENDPOINTS (DADOS) ---

// (GET /api/chamados - continua igual)
app.get('/api/chamados', autenticarToken, async (req, res) => {
  const usuario = req.usuario;
  
  // 1. LÊ O PARÂMETRO DA URL
  const { status } = req.query; 

  try {
    let sql;
    let params = [];

    // ... (lógica de if/else para 'tecnico' vs 'funcionario') ...
    if (usuario.nivel === 'tecnico' || usuario.nivel === 'admin') {
      console.log(`[Visão TI] Buscando chamados...`);
      sql = 'SELECT * FROM chamados';
      
      // 2. ADICIONA O FILTRO (SE EXISTIR)
      if (status) {
        sql += ' WHERE status = ?';
        params.push(status);
      } else {
        // --- ESTA PODE SER A CORREÇÃO ---
        // Se o seu filtro padrão é 'aberto',
        // talvez a lógica para 'todos' esteja errada.
        // Vamos garantir que se 'status' for uma string vazia, não filtramos.
      }

    } else {
      // Lógica do Funcionário
      console.log(`[Visão Funcionário] Buscando chamados do usuário ${usuario.id}...`);
      sql = 'SELECT * FROM chamados WHERE criado_por_id = ?';
      params.push(usuario.id);

      // 3. ADICIONA O FILTRO DE STATUS (SE EXISTIR)
      if (status) {
        sql += ' AND status = ?';
        params.push(status);
      }
    }

    // 4. Adiciona a ordenação
    sql += ' ORDER BY criado_em DESC';

    // 5. Log de depuração
    console.log(`Executando SQL: ${sql} com parâmetros: [${params.join(', ')}]`);
    
    const [rows] = await pool.query(sql, params);
    
    console.log(`Query executada, ${rows.length} chamados encontrados (Filtro: ${status || 'nenhum'}).`);
    
    res.json(rows);

  } catch (err) {
    console.error('Erro ao buscar chamados:', err);
    res.status(500).json({ message: 'Erro ao buscar dados' });
  }
});

// GET /api/chamado/:id (ATUALIZADO COM JOIN PARA NOME DO TÉCNICO)
app.get('/api/chamado/:id', autenticarToken, apenasTecnicos, async (req, res) => {
  const chamadoId = req.params.id;
  try {
    // Adicionámos um SEGUNDO JOIN (p_tecnico) para buscar o nome do técnico atribuído
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
    res.json(rows[0]);
  } catch (err) {
    console.error('Erro ao buscar detalhe do chamado:', err);
    res.status(500).json({ message: 'Erro ao buscar dados' });
  }
});

// --- ROTA NOVA PARA BUSCAR A LISTA DE TÉCNICOS ---
app.get('/api/tecnicos', autenticarToken, apenasTecnicos, async (req, res) => {
  console.log('Recebida requisição para GET /api/tecnicos'); // Log de depuração
  try {
    // Query correta: Busca ID e nome_completo da tabela PERFIS
    // onde o nível é 'tecnico' OU 'admin'
    const sql = "SELECT id, nome_completo FROM perfis WHERE nivel = 'tecnico' OR nivel = 'admin' ORDER BY nome_completo";
    
    const [rows] = await pool.query(sql);
    
    console.log(`Encontrados ${rows.length} técnicos.`); // Log de depuração
    res.json(rows);

  } catch (err) {
    console.error('Erro ao buscar técnicos:', err);
    res.status(500).json({ message: 'Erro ao buscar dados' });
  }
});
// POST /api/chamado (com upload)
app.post('/api/chamado', autenticarToken, upload.single('anexo'), async (req, res) => {
  // ... (o seu código de criar chamado continua igual)
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

// PUT /api/chamados/:id/atribuir (ATUALIZADO)
// Agora espera um 'tecnicoId' no corpo da requisição
app.put('/api/chamados/:id/atribuir', autenticarToken, apenasTecnicos, async (req, res) => {
  const chamadoId = req.params.id;
  const { tecnicoId } = req.body; // Pega o ID do técnico selecionado no dropdown

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

// (O resto do seu server.js: /status, /register, /login, app.listen)
// ...
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

app.post('/api/register', async (req, res) => {
  // ... (código de registro)
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
  // ... (código de login)
  const { email, pass } = req.body;
  if (!email || !pass) {
    return res.status(400).json({ message: 'Email e senha são obrigatórios.' });
  }
  try {
    const [rows] = await pool.query(
      `SELECT u.id, u.email, u.senha_hash, p.nivel, p.setor_texto, p.cargo_texto 
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
      nivel: usuario.nivel,
      setor: usuario.setor_texto,
      cargo: usuario.cargo_texto
    };
    const token = jwt.sign(
      payload, 
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );
    res.json({ message: 'Login bem-sucedido!', token: token });
  } catch (err) {
    console.error('Erro no login:', err);
    res.status(500).json({ message: 'Erro interno no servidor.' });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor Node.js (com MySQL) rodando em http://localhost:${PORT}`);
});