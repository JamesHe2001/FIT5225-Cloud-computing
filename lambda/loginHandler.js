// loginHandler.js
const AWS = require('aws-sdk');
const bcrypt = require('bcryptjs');

const dynamo = new AWS.DynamoDB.DocumentClient();
const USERS_TABLE = 'Users';

exports.handler = async (event) => {
  try {
    const body = JSON.parse(event.body);
    const { email, password } = body;

    const result = await dynamo.get({
      TableName: USERS_TABLE,
      Key: { email }
    }).promise();

    const user = result.Item;

    if (!user) {
      return {
        statusCode: 401,
        body: JSON.stringify({ message: "Invalid email or password" })
      };
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return {
        statusCode: 401,
        body: JSON.stringify({ message: "Invalid email or password" })
      };
    }

    const token = "dummy-jwt-token"; 

    return {
      statusCode: 200,
      body: JSON.stringify({ token })
    };

  } catch (error) {
    console.error("Login error:", error);
    return {
      statusCode: 500,
      body: JSON.stringify({ message: "Internal server error" })
    };
  }
};