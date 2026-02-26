const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/authenticate');
const { OrderCreateSchema, OrderUpdateSchema } = require('../validators/schemas');
const { sendEmail } = require('../services/emailService');

module.exports = ({ pgClient, readJSON, writeJSON, ordersPath, logger }) => {
  // GET - List all orders (protected)
  router.get('/', authenticate, async (req, res) => {
    try {
      if (pgClient) {
        const { rows } = await pgClient.query('SELECT * FROM food_orders ORDER BY created_at DESC');
        return res.json(rows);
      }
      const orders = readJSON(ordersPath, []);
      return res.json(orders);
    } catch (e) {
      logger.error('GET /api/orders error', e.message);
      res.status(500).json({ error: 'server_error' });
    }
  });

  // POST - Create order (public, but validates)
  router.post('/', async (req, res) => {
    try {
      const payload = OrderCreateSchema.parse(req.body);
      
            // Send confirmation email if email provided
            if (payload.customerEmail) {
              sendEmail(payload.customerEmail, 'orderConfirmation', payload, logger).catch(err => {
                logger.warn('Failed to send order confirmation email', err.message);
              });
            }
      
      if (pgClient) {
        const q = `INSERT INTO food_orders (customer_name, customer_email, customer_phone, order_type, order_date, delivery_date, delivery_address, items, subtotal, delivery_fee, tax, total_amount, status, payment_status, payment_method, created_at)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,now()) RETURNING *`;
        const values = [payload.customerName, payload.customerEmail||null, payload.customerPhone||null, payload.orderType||'dine-in', payload.orderDate||new Date().toISOString(), payload.deliveryDate||null, payload.deliveryAddress||null, JSON.stringify(payload.items||[]), payload.subtotal||0, payload.deliveryFee||0, payload.tax||0, payload.totalAmount||0, payload.status||'pending', payload.paymentStatus||'pending', payload.paymentMethod||null];
        const { rows } = await pgClient.query(q, values);
        return res.status(201).json(rows[0]);
      }
      const orders = readJSON(ordersPath, []);
      const id = `ORDER-${Date.now()}`;
      const created = { id, customerName: payload.customerName, customerEmail: payload.customerEmail||null, customerPhone: payload.customerPhone||null, orderType: payload.orderType||'dine-in', orderDate: payload.orderDate||new Date().toISOString(), deliveryDate: payload.deliveryDate||null, deliveryAddress: payload.deliveryAddress||null, items: payload.items||[], subtotal: payload.subtotal||0, deliveryFee: payload.deliveryFee||0, tax: payload.tax||0, totalAmount: payload.totalAmount||0, status: payload.status||'pending', paymentStatus: payload.paymentStatus||'pending', paymentMethod: payload.paymentMethod||null, createdAt: new Date().toISOString() };
      orders.unshift(created);
      writeJSON(ordersPath, orders);
      return res.status(201).json(created);
    } catch (e) {
      if (e.name === 'ZodError') {
        return res.status(400).json({ error: 'Validation error', details: e.errors });
      }
      logger.error('POST /api/orders error', e.message);
      res.status(500).json({ error: 'server_error' });
    }
  });

  // PUT - Update order (protected)
  router.put('/:id', authenticate, async (req, res) => {
    try {
      const id = req.params.id;
      const payload = OrderUpdateSchema.parse(req.body);
      if (pgClient) {
        const updates = [];
        const values = [];
        let idx = 1;
        for (const k of ['status','paymentStatus']) {
          if (payload[k] !== undefined) { updates.push(`${k} = $${idx++}`); values.push(payload[k]); }
        }
        if (payload.items !== undefined) { updates.push(`items = $${idx++}`); values.push(JSON.stringify(payload.items)); }
        if (updates.length === 0) return res.status(400).json({ error: 'no_updates' });
        const q = `UPDATE food_orders SET ${updates.join(',')}, updated_at = now() WHERE id = $${idx} RETURNING *`;
        values.push(id);
        const { rows } = await pgClient.query(q, values);
        if (rows.length === 0) return res.status(404).json({ error: 'not_found' });
        return res.json(rows[0]);
      }
      const orders = readJSON(ordersPath, []);
      const idx = orders.findIndex(o => o.id === id);
      if (idx === -1) return res.status(404).json({ error: 'not_found' });
      orders[idx] = { ...orders[idx], ...payload, updatedAt: new Date().toISOString() };
      writeJSON(ordersPath, orders);
      return res.json(orders[idx]);
    } catch (e) {
      if (e.name === 'ZodError') {
        return res.status(400).json({ error: 'Validation error', details: e.errors });
      }
      logger.error('PUT /api/orders/:id error', e.message);
      res.status(500).json({ error: 'server_error' });
    }
  });

  return router;
};
