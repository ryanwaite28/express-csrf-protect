const express = require('express');
const expressCsrf = require('./index');
 
const app = express();

app.use(expressCsrf.enable());


app.get('/', (request, response) => {
  return response.json({ message: 'admit one' });
});

app.post('/', (request, response) => {
  return response.json({ message: 'admit one' });
});



const PORT = process.env.PORT || 3000;
app.listen(PORT);
console.log(`Listening on port ${PORT}...\n\n`);