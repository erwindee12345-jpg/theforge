const express = require('express');
const bodyParser = require('body-parser');
const app = express();

app.use(bodyParser.urlencoded({ extended: true }));

app.post('/update-email', (req, res) => {
  const newEmail = req.body.email;
  const userId = req.session.userId; // Assume user is authenticated

  // Update user's email in the database
  // db.updateUserEmail(userId, newEmail);

  res.send('Email updated successfully');
});

app.listen(3000, () => console.log('Server running on port 3000'));