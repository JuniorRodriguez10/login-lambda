const AWS = require('aws-sdk');
const bcrypt = require('bcryptjs');

// DocumentClient permite trabajar con objetos JS en DynamoDB
const dynamo = new AWS.DynamoDB.DocumentClient();
const USERS_TABLE = process.env.TABLE_USER || 'Users';

exports.handler = async (event) => {
  try {
    // Validar que llegue body
    if (!event.body) {
      return { statusCode: 400, body: JSON.stringify({ message: 'Falta el body en la petición' }) };
    }
    const { email, password } = JSON.parse(event.body);
    if (!email || !password) {
      return { statusCode: 400, body: JSON.stringify({ message: 'Email y password son requeridos' }) };
    }

    // Escanea la tabla para encontrar el email (no requiere GSI)
    const result = await dynamo.scan({
      TableName: USERS_TABLE,
      FilterExpression: 'email = :email',
      ExpressionAttributeValues: { ':email': email }
    }).promise();

    if (!result.Items || result.Items.length === 0) {
      return { statusCode: 401, body: JSON.stringify({ message: 'Credenciales inválidas' }) };
    }

    const user = result.Items[0];
    // Compara hashes
    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) {
      return { statusCode: 401, body: JSON.stringify({ message: 'Credenciales inválidas' }) };
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ message: 'Login exitoso', userId: user.uuid })
    };
  } catch (err) {
    console.error('Error en login.js:', err);
    return { statusCode: 500, body: JSON.stringify({ message: 'Error interno al iniciar sesión' }) };
  }
};