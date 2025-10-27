// registerHandler.js (Node.js 18+ runtime assumed)
const AWS = require('aws-sdk');
const bcrypt = require('bcryptjs');

const dynamo = new AWS.DynamoDB.DocumentClient();
const USERS_TABLE = 'Users'; 

exports.handler = async (event) => {
  try {
    const body = JSON.parse(event.body);
    const { firstname, lastname, email, password } = body;

    if (!firstname || !lastname || !email || !password) {
      return {
        statusCode: 400,
        body: JSON.stringify({ message: 'Missing required fields.' })
      };
    }

    const existing = await dynamo.get({
      TableName: USERS_TABLE,
      Key: { email }
    }).promise();

    if (existing.Item) {
      return {
        statusCode: 409,
        body: JSON.stringify({ message: 'Email is already registered.' })
      };
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await dynamo.put({
      TableName: USERS_TABLE,
      Item: {
        email,
        firstname,
        lastname,
        password: hashedPassword
      }
    }).promise();

    return {
      statusCode: 201,
      body: JSON.stringify({ message: 'User registered successfully.' })
    };

  } catch (error) {
    console.error('Registration error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ message: 'Internal server error.' })
    };
  }
};