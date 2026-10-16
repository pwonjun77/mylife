// 의도적으로 취약하게 작성한 예제 코드입니다.
const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/search', (req, res) => {
  db.query("SELECT * FROM items WHERE name = '" + req.query.q + "'");
  res.set('Access-Control-Allow-Origin', '*');
});

app.get('/run', (req, res) => {
  exec(`ls ${req.query.dir}`);
});

app.post('/users', async (req, res) => {
  const user = await User.findOne(req.body);
  res.cookie('sid', user.id, { httpOnly: false, secure: false });
});

function render(msg) {
  document.getElementById('out').innerHTML = msg;
  const resetToken = Math.random().toString(36);
}
