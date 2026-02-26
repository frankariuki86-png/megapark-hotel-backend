const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Megapark Hotel API',
      version: '1.0.0',
      description: 'Complete API documentation for Megapark Resort management system',
      contact: {
        name: 'Megapark Team',
        email: 'support@megapark.com'
      }
    },
    servers: [
      {
        url: 'http://localhost:3000',
        description: 'Development server'
      },
      {
        url: 'https://api.megapark.com',
        description: 'Production server'
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      },
      schemas: {
        Error: {
          type: 'object',
          properties: {
            error: { type: 'string' },
            status: { type: 'integer' }
          }
        },
        User: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            email: { type: 'string' },
            name: { type: 'string' },
            role: { type: 'string', enum: ['admin', 'user'] }
          }
        },
        MenuItem: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            name: { type: 'string' },
            description: { type: 'string' },
            category: { type: 'string' },
            price: { type: 'number' },
            availability: { type: 'boolean' },
            createdAt: { type: 'string', format: 'date-time' }
          }
        },
        Order: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            customerName: { type: 'string' },
            items: { type: 'array' },
            totalAmount: { type: 'number' },
            status: { type: 'string', enum: ['pending', 'confirmed', 'preparing', 'ready', 'delivered', 'cancelled'] },
            createdAt: { type: 'string', format: 'date-time' }
          }
        }
      }
    }
  },
  apis: ['./routes/*.js', './index.js']
};

const specs = swaggerJsdoc(options);

module.exports = { swaggerUi, specs };
