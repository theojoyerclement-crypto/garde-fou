const express = require('express');
const { requireAuth } = require('./middleware');
const aiRouter = require('./routes/ai');

const app = express();
app.use(express.json());
app.use('/api', requireAuth, aiRouter);
app.listen(3000);
