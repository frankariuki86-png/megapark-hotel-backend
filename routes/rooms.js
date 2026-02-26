const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/authenticate');
const { RoomCreateSchema, RoomUpdateSchema } = require('../validators/schemas');

module.exports = ({ pgClient, readJSON, writeJSON, roomsPath, logger }) => {
  logger.info('[roomsRouter] Exported function called');
  
  // Test endpoint to verify router is mounted
  router.get('/test', (req, res) => {
    logger.info('GET /api/rooms/test - Router is mounted and working!');
    return res.json({ status: 'ok', message: 'Rooms router is mounted successfully' });
  });

  // GET - List all rooms (public)
  router.get('/', async (req, res) => {
    try {
      logger.info('[Rooms GET /] Endpoint handler called on server');
      logger.info('GET /api/rooms - pgClient available:', !!pgClient);
      if (pgClient) {
        try {
          const { rows } = await pgClient.query('SELECT * FROM rooms ORDER BY created_at DESC');
          logger.info('GET /api/rooms - DB query successful, rows:', rows.length);
          return res.json(rows);
        } catch (dbErr) {
          logger.warn('GET /api/rooms - DB query failed, falling back to JSON:', dbErr.message);
        }
      }
      const rooms = readJSON(roomsPath, []);
      logger.info('GET /api/rooms - Returning', rooms.length, 'rooms from JSON file');
      return res.json(rooms);
    } catch (e) {
      logger.error('GET /api/rooms error', e.message);
      res.status(500).json({ error: 'server_error' });
    }
  });

  // POST - Create room (protected)
  router.post('/', authenticate, async (req, res) => {
    try {
      const payload = RoomCreateSchema.parse(req.body);
      
      if (pgClient) {
        const q = `INSERT INTO rooms (room_number, name, type, description, price_per_night, images, amenities, capacity, availability, created_at)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now()) RETURNING *`;
        const values = [
          payload.roomNumber,
          payload.name, 
          payload.type,
          payload.description||'', 
          payload.pricePerNight, 
          JSON.stringify(payload.images || []), 
          JSON.stringify(payload.amenities || []),
          payload.capacity,
          payload.availability !== false,
        ];
        const { rows } = await pgClient.query(q, values);
        return res.status(201).json(rows[0]);
      }
      const rooms = readJSON(roomsPath, []);
      const id = `room-${Date.now()}`;
      const created = { id, ...payload, createdAt: new Date().toISOString() };
      rooms.unshift(created);
      writeJSON(roomsPath, rooms);
      return res.status(201).json(created);
    } catch (e) {
      if (e.name === 'ZodError') {
        return res.status(400).json({ error: 'Validation error', details: e.errors });
      }
      logger.error('POST /api/rooms error', e.message);
      res.status(500).json({ error: 'server_error' });
    }
  });

  // PUT - Update room (protected)
  router.put('/:id', authenticate, async (req, res) => {
    try {
      const id = req.params.id;
      const payload = RoomUpdateSchema.parse(req.body);
      
      if (pgClient) {
        const updates = [];
        const values = [];
        let idx = 1;
        for (const [k, v] of Object.entries(payload)) {
          if (v !== undefined) {
            let col = k;
            if (k === 'roomNumber') col = 'room_number';
            if (k === 'pricePerNight') col = 'price_per_night';
            
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
        const q = `UPDATE rooms SET ${updates.join(',')}, updated_at = now() WHERE id = $${idx} RETURNING *`;
        values.push(id);
        const { rows } = await pgClient.query(q, values);
        if (rows.length === 0) return res.status(404).json({ error: 'not_found' });
        return res.json(rows[0]);
      }
      const rooms = readJSON(roomsPath, []);
      const idx = rooms.findIndex(it => it.id === id);
      if (idx === -1) return res.status(404).json({ error: 'not_found' });
      rooms[idx] = { ...rooms[idx], ...payload, updatedAt: new Date().toISOString() };
      writeJSON(roomsPath, rooms);
      return res.json(rooms[idx]);
    } catch (e) {
      if (e.name === 'ZodError') {
        return res.status(400).json({ error: 'Validation error', details: e.errors });
      }
      logger.error('PUT /api/rooms/:id error', e.message);
      res.status(500).json({ error: 'server_error' });
    }
  });

  // DELETE - Delete room (protected)
  router.delete('/:id', authenticate, async (req, res) => {
    try {
      const id = req.params.id;
      if (pgClient) {
        const result = await pgClient.query('DELETE FROM rooms WHERE id = $1', [id]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'not_found' });
        return res.status(204).send();
      }
      const rooms = readJSON(roomsPath, []);
      const idx = rooms.findIndex(it => it.id === id);
      if (idx === -1) return res.status(404).json({ error: 'not_found' });
      rooms.splice(idx, 1);
      writeJSON(roomsPath, rooms);
      return res.status(204).send();
    } catch (e) {
      logger.error('DELETE /api/rooms/:id error', e.message);
      res.status(500).json({ error: 'server_error' });
    }
  });

  return router;
};
