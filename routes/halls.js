const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/authenticate');
const { HallCreateSchema, HallUpdateSchema } = require('../validators/schemas');

module.exports = ({ pgClient, readJSON, writeJSON, hallsPath, logger }) => {
  logger.info('[hallsRouter] Exported function called');
  
  // Test endpoint to verify router is mounted
  router.get('/test', (req, res) => {
    logger.info('GET /api/halls/test - Router is mounted and working!');
    return res.json({ status: 'ok', message: 'Halls router is mounted successfully' });
  });

  // GET - List all halls (public)
  router.get('/', async (req, res) => {
    try {
      logger.info('[Halls GET /] Endpoint handler called on server');
      logger.info('GET /api/halls - pgClient available:', !!pgClient);
      if (pgClient) {
        try {
          const { rows } = await pgClient.query('SELECT * FROM halls ORDER BY created_at DESC');
          logger.info('GET /api/halls - DB query successful, rows:', rows.length);
          return res.json(rows);
        } catch (dbErr) {
          logger.warn('GET /api/halls - DB query failed, falling back to JSON:', dbErr.message);
        }
      }
      const halls = readJSON(hallsPath, []);
      logger.info('GET /api/halls - Returning', halls.length, 'halls from JSON file');
      return res.json(halls);
    } catch (e) {
      logger.error('GET /api/halls error', e.message);
      res.status(500).json({ error: 'server_error' });
    }
  });

  // POST - Create hall (protected)
  router.post('/', authenticate, async (req, res) => {
    try {
      const payload = HallCreateSchema.parse(req.body);
      
      if (pgClient) {
        const q = `INSERT INTO halls (name, description, capacity, price_per_day, images, amenities, availability, created_at)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,now()) RETURNING *`;
        const values = [
          payload.name, 
          payload.description||'', 
          payload.capacity, 
          payload.pricePerDay, 
          JSON.stringify(payload.images || []), 
          JSON.stringify(payload.amenities || []),
          payload.availability !== false,
        ];
        const { rows } = await pgClient.query(q, values);
        return res.status(201).json(rows[0]);
      }
      const halls = readJSON(hallsPath, []);
      const id = `hall-${Date.now()}`;
      const created = { id, ...payload, createdAt: new Date().toISOString() };
      halls.unshift(created);
      writeJSON(hallsPath, halls);
      return res.status(201).json(created);
    } catch (e) {
      if (e.name === 'ZodError') {
        return res.status(400).json({ error: 'Validation error', details: e.errors });
      }
      logger.error('POST /api/halls error', e.message);
      res.status(500).json({ error: 'server_error' });
    }
  });

  // PUT - Update hall (protected)
  router.put('/:id', authenticate, async (req, res) => {
    try {
      const id = req.params.id;
      const payload = HallUpdateSchema.parse(req.body);
      
      if (pgClient) {
        const updates = [];
        const values = [];
        let idx = 1;
        for (const [k, v] of Object.entries(payload)) {
          if (v !== undefined) {
            const col = k === 'pricePerDay' ? 'price_per_day' : k;
            if (Array.isArray(v)) {
              updates.push(`${col} = $${idx++}`);
              values.push(JSON.stringify(v));
            } else {
              updates.push(`${col} = $${idx++}`);
              values.push(v);
            }
          }
        }
        if (updates.length === 0) return res.status(400).json({ error: 'no_updates' });
        const q = `UPDATE halls SET ${updates.join(',')}, updated_at = now() WHERE id = $${idx} RETURNING *`;
        values.push(id);
        const { rows } = await pgClient.query(q, values);
        if (rows.length === 0) return res.status(404).json({ error: 'not_found' });
        return res.json(rows[0]);
      }
      const halls = readJSON(hallsPath, []);
      const idx = halls.findIndex(it => it.id === id);
      if (idx === -1) return res.status(404).json({ error: 'not_found' });
      halls[idx] = { ...halls[idx], ...payload, updatedAt: new Date().toISOString() };
      writeJSON(hallsPath, halls);
      return res.json(halls[idx]);
    } catch (e) {
      if (e.name === 'ZodError') {
        return res.status(400).json({ error: 'Validation error', details: e.errors });
      }
      logger.error('PUT /api/halls/:id error', e.message);
      res.status(500).json({ error: 'server_error' });
    }
  });

  // DELETE - Delete hall (protected)
  router.delete('/:id', authenticate, async (req, res) => {
    try {
      const id = req.params.id;
      if (pgClient) {
        const result = await pgClient.query('DELETE FROM halls WHERE id = $1', [id]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'not_found' });
        return res.status(204).send();
      }
      const halls = readJSON(hallsPath, []);
      const idx = halls.findIndex(it => it.id === id);
      if (idx === -1) return res.status(404).json({ error: 'not_found' });
      halls.splice(idx, 1);
      writeJSON(hallsPath, halls);
      return res.status(204).send();
    } catch (e) {
      logger.error('DELETE /api/halls/:id error', e.message);
      res.status(500).json({ error: 'server_error' });
    }
  });

  return router;
};
