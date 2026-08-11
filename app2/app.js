require('dotenv').config();

const http = require('http');

const name = process.env.NAME;
const port = process.env.PORT || 9100;

const server = http.createServer((req, res) => {
   res.writeHead(200, {
       'content-type': 'text/plain'
   });

   res.end(`hello from ${name}!`);

});

server.listen(port, () => {
    console.log(`${name} running on port ${port}`);
});
