const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/authenticate');
const { MenuItemCreateSchema, MenuItemUpdateSchema } = require('../validators/schemas');

module.exports = ({ pgClient, readJSON, writeJSON, menuPath, logger }) => {
  logger.info('[menuRouter] Exported function called');
  
  // Test endpoint to verify router is mounted
  router.get('/test', (req, res) => {
    logger.info('GET /api/menu/test - Router is mounted and working!');
    return res.json({ status: 'ok', message: 'Menu router is mounted successfully' });
  });

  // GET - List all menu items (public)
  router.get('/', async (req, res) => {
    try {
      logger.info('[Menu GET /] Endpoint handler called on server');
      logger.info('GET /api/menu - pgClient available:', !!pgClient);
      if (pgClient) {
        try {
          const { rows } = await pgClient.query('SELECT * FROM menu_items ORDER BY created_at DESC');
          logger.info('GET /api/menu - DB query successful, rows:', rows.length);
          return res.json(rows);
        } catch (dbErr) {
          logger.warn('GET /api/menu - DB query failed, falling back to JSON:', dbErr.message);
          // Fall through to JSON file
        }
      }
      const items = readJSON(menuPath, []);
      logger.info('GET /api/menu - Returning', items.length, 'items from JSON file');
      return res.json(items);
    } catch (e) {
      logger.error('GET /api/menu error', e.message);
      res.status(500).json({ error: 'server_error' });
    }
  });

  // POST - Create menu item (protected)
  router.post('/', authenticate, async (req, res) => {
    try {
      const payload = MenuItemCreateSchema.parse(req.body);
      
      if (pgClient) {
        const q = `INSERT INTO menu_items (name, description, category, price, image, availability, preparation_time, created_at)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,now()) RETURNING *`;
        const values = [payload.name, payload.description||'', payload.category, payload.price, payload.image||null, true, payload.preparationTime];
        const { rows } = await pgClient.query(q, values);
        return res.status(201).json(rows[0]);
      }
      const items = readJSON(menuPath, []);
      const id = `menu-${Date.now()}`;
      const created = { id, ...payload, createdAt: new Date().toISOString() };
      items.unshift(created);
      writeJSON(menuPath, items);
      return res.status(201).json(created);
    } catch (e) {
      if (e.name === 'ZodError') {
        return res.status(400).json({ error: 'Validation error', details: e.errors });
      }
      logger.error('POST /api/menu error', e.message);
      res.status(500).json({ error: 'server_error' });
    }
  });

  // PUT - Update menu item (protected)
  router.put('/:id', authenticate, async (req, res) => {
    try {
      const id = req.params.id;
      const payload = MenuItemUpdateSchema.parse(req.body);
      
      if (pgClient) {
        const updates = [];
        const values = [];
        let idx = 1;
        for (const [k, v] of Object.entries(payload)) {
          if (v !== undefined) {
            const col = k === 'preparationTime' ? 'preparation_time' : k;
            updates.push(`${col} = $${idx++}`);
            values.push(v);
          }
        }
        if (updates.length === 0) return res.status(400).json({ error: 'no_updates' });
        const q = `UPDATE menu_items SET ${updates.join(',')}, updated_at = now() WHERE id = $${idx} RETURNING *`;
        values.push(id);
        const { rows } = await pgClient.query(q, values);
        if (rows.length === 0) return res.status(404).json({ error: 'not_found' });
        return res.json(rows[0]);
      }
      const items = readJSON(menuPath, []);
      const idx = items.findIndex(it => it.id === id);
      if (idx === -1) return res.status(404).json({ error: 'not_found' });
      items[idx] = { ...items[idx], ...payload, updatedAt: new Date().toISOString() };
      writeJSON(menuPath, items);
      return res.json(items[idx]);
    } catch (e) {
      if (e.name === 'ZodError') {
        return res.status(400).json({ error: 'Validation error', details: e.errors });
      }
      logger.error('PUT /api/menu/:id error', e.message);
      res.status(500).json({ error: 'server_error' });
    }
  });

  // DELETE - Delete menu item (protected)
  router.delete('/:id', authenticate, async (req, res) => {
    try {
      const id = req.params.id;
      if (pgClient) {
        const result = await pgClient.query('DELETE FROM menu_items WHERE id = $1', [id]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'not_found' });
        return res.status(204).send();
      }
      const items = readJSON(menuPath, []);
      const idx = items.findIndex(it => it.id === id);
      if (idx === -1) return res.status(404).json({ error: 'not_found' });
      items.splice(idx, 1);
      writeJSON(menuPath, items);
      return res.status(204).send();
    } catch (e) {
      logger.error('DELETE /api/menu/:id error', e.message);
      res.status(500).json({ error: 'server_error' });
    }
  });

  return router;
};
