# Render Chat App

A responsive real-time chat application built with Node.js, Express, Socket.IO and PostgreSQL.

## Features

- Registration and login
- Secure password hashing with bcrypt
- JWT authentication using an HTTP-only cookie
- Real-time one-to-one messaging with Socket.IO
- Online/offline presence
- Conversation list
- Message history stored in PostgreSQL
- Mobile responsive interface
- Logout
- Render deployment configuration
- Automatic database table initialization

## Deploy on Render

1. Create a PostgreSQL database in Render.
2. Create a Web Service from this project/repository.
3. Build command: `npm install`
4. Start command: `npm start`
5. Add environment variables:
   - `DATABASE_URL` = your Render PostgreSQL internal connection string
   - `JWT_SECRET` = a long random secret
   - `NODE_ENV` = `production`
6. Deploy.

The server listens on Render's `PORT` environment variable.

## Local development

```bash
npm install
cp .env.example .env
npm start
```

Open `http://localhost:10000`.

## Notes

For a production multi-instance deployment, use a Socket.IO-compatible pub/sub adapter such as Redis. A single Render web instance works without it.
