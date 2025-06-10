# RESTaurante authentication API
Esta API fornece endpoints para registro, login, e gerenciamento de usuários via JWT.

## Tecnologias
- Node.js
- Express
- MongoDB + Mongoose
- JWT (autenticação)
- Joi (validação)

## Instalação

```bash
git clone https://github.com/opghostone/restaurante
cd restaurante
npm install
```

<p>Crie um arquivo .env com:</p>

```bash
PORT=8080
MONGODB_URL=url para sua db
SECRET=uma_senha_bem_secreta
```

<p>Para conseguir sua URL para se conectar ao banco de dados:</p>
https://youtu.be/SMXbGrKe5gM

<p>Para rodar:</p>

```bash
npm start
```

## Autenticação

Algumas rotas da API são **protegidas por autenticação JWT**. Para acessá-las, você precisará fornecer um token válido no cabeçalho da requisição HTTP.

### Estrutura do Token JWT

Os tokens gerados pela API são compostos por três partes codificadas em base64 estruturadas da seguinte forma:

1. **Header** 

   ```json
   {
     "alg": "HS256",
     "typ": "JWT"
   }
   ```

2. **Payload**

   ```json
   {
     "_id": "1234",
     "username": "Joao",
     "email": "joao@example.com"
   }
   ```

3. **Signature**

   A assinatura é um hash gerado com base no header, payload e uma chave secreta privada, garantindo a integridade do token.

### Como usar o token

Para acessar rotas protegidas, insira o token JWT no cabeçalho `Authorization` da sua requisição HTTP, conforme o exemplo abaixo:

```
Authorization: <seu_token_jwt>
```

Substitua `<seu_token_jwt>` pelo token real fornecido pela API após o login, sem nenhum prefixo.

## Endpoints

### `POST /register`

Cria um novo usuário.

#### Body

```json
{
  "username": "João da Silva",
  "email": "joao@example.com",
  "password": "senhaSegura123"
}
```

#### Respostas

| Código | Descrição |
|--------|-----------|
| 200    | Usuário criado com sucesso |
| 400    | Usuário já existe / entrada inválida / propriedade ausente |

---

### `POST /login`

Autentica um usuário e retorna um token JWT.

#### Body

```json
{
  "email": "joao@example.com",
  "password": "senhaSegura123"
}
```

#### Resposta

```json
{
  "token": "jwt_token_aqui"
}
```

| Código | Descrição |
|--------|-----------|
| 200    | Login realizado com sucesso |
| 400    | Dados inválidos ou ausentes / Usuário não encontrado|
| 401    | Senha incorreta |

---

### `GET /users/:id`

Retorna os dados de um usuário autenticado.

#### Cabeçalho

```
Authorization: <jwt_token>
```

#### Resposta

```json
{
  "username": "João da Silva",
  "email": "joao@example.com",
  "id": "abc123"
}
```

| Código | Descrição |
|--------|-----------|
| 200    | Sucesso |
| 401    | Token ausente ou inválido |
| 404    | Usuário não encontrado |

---

### `PATCH /users/:id`

Atualiza a senha do usuário autenticado.

#### Cabeçalho

```
Authorization: <jwt_token>
```

#### Body

```json
{
  "password": "novaSenha123"
}
```

| Código | Descrição |
|--------|-----------|
| 200    | Senha atualizada |
| 400    | Nenhuma senha fornecida |
| 401    | Acesso não autorizado |

---

### `DELETE /users/:id`

Remove o usuário autenticado.

#### Cabeçalho

```
Authorization: <jwt_token>
```

| Código | Descrição |
|--------|-----------|
| 200    | Usuário deletado com sucesso |
| 401    | Acesso não autorizado |

---

## Padrão de Validação

- `username`: letras e espaços, 1–64 caracteres
- `email`: formato de e-mail válido
- `password`: entre 8 e 32 caracteres

---
