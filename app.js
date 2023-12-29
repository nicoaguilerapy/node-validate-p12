const express = require('express');
const multer = require('multer');
const fs = require('fs');
const forge = require('node-forge');

const app = express();
const port = process.env.PORT || 3000;

// Configuración de Multer para manejar archivos
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Servir archivos estáticos desde la carpeta 'public'
app.use(express.static('public'));

app.post('/verificar', upload.single('archivo'), (req, res) => {
  try {
    const contrasena = req.body.pass;
    const p12Data = req.file.buffer;

    const p12Asn1 = forge.asn1.fromDer(p12Data.toString('binary'));
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, contrasena);

    const bags = p12.getBags({ bagType: forge.pki.oids.certBag });

    if (bags[forge.pki.oids.certBag]) {
      res.json({ message: 'La contraseña es correcta.' });
    } else {
      res.status(401).json({ message: 'La contraseña es incorrecta o el archivo P12 es inválido.' });
    }
  } catch (error) {
    console.error('Error:', error.message);
    res.status(500).json({ message: 'Error interno del servidor.' });
  }
});

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/templates/index.html');
});

app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});
