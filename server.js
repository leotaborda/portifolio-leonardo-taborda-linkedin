// server.js
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const path = require("path");

const app = express();
const db = new sqlite3.Database("database.db"); // Banco de dados persistente

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public")); // Pasta para arquivos frontend

// Configurações de sessão
app.use(
    session({
        secret: "segredo_super_secreto",
        resave: false,
        saveUninitialized: true,
    })
);

// Inicializa o banco de dados
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, nome TEXT, email TEXT, titulo TEXT, mensagem TEXT)");

    // Adiciona um admin padrão (username: admin, password: admin!001) se não existir
    db.get("SELECT * FROM admin WHERE username = ?", ["admin"], (err, row) => {
        if (!row) {
            const hashedPassword = bcrypt.hashSync("admin!001", 10);
            db.run("INSERT INTO admin (username, password) VALUES (?, ?)", ["admin", hashedPassword]);
        }
    });
});

// Middleware para verificar se o usuário está logado
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        return next();
    }
    res.redirect("/login.html");
}

// Rota para login
app.post("/login", (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM admin WHERE username = ?", [username], (err, user) => {
        if (err) return res.status(500).send("Erro no servidor");
        if (user && bcrypt.compareSync(password, user.password)) {
            req.session.userId = user.id;
            res.redirect("/admin.html");
        } else {
            res.send("Usuário ou senha inválidos");
        }
    });
});

// Rota para salvar mensagem
app.post("/send-message", (req, res) => {
    const { nome, email, titulo, mensagem } = req.body;
    db.run(
        "INSERT INTO messages (nome, email, titulo, mensagem) VALUES (?, ?, ?, ?)",
        [nome, email, titulo, mensagem],
        function (err) {
            if (err) return res.status(500).send("Erro ao salvar mensagem");
            res.send("Mensagem enviada com sucesso!");
        }
    );
});

// Rota para ver mensagens (somente logado)
app.get("/messages", isAuthenticated, (req, res) => {
    db.all("SELECT * FROM messages", (err, rows) => {
        if (err) return res.status(500).send("Erro ao buscar mensagens");
        res.json(rows);
    });
});

// Rota para logout
app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/login.html");
});

// Rota para verificar a sessão do usuário
app.get("/check-session", (req, res) => {
    if (req.session.userId) {
        res.json({ authenticated: true });
    } else {
        res.json({ authenticated: false });
    }
});

// Rota para deletar uma mensagem
app.delete("/message/:id", (req, res) => {
    const messageId = req.params.id;

    db.run("DELETE FROM messages WHERE id = ?", [messageId], function (err) {
        if (err) {
            res.status(500).send("Erro ao excluir a mensagem");
        } else {
            res.send("Mensagem excluída com sucesso!");
        }
    });
});

// Inicia o servidor e exibe o link completo
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
});
