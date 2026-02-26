const express = require('express');
const router = express.Router();
const { authenticate } = require('../middleware/authenticate');
const { BookingCreateSchema, BookingUpdateSchema } = require('../validators/schemas');
const { sendRoomBookingConfirmationEmail, sendHallBookingConfirmationEmail } = require('../services/emailService');

module.exports = ({ pgClient, readJSON, writeJSON, bookingsPath, logger }) => {
  // GET - list bookings (protected)
  router.get('/', authenticate, async (req, res) => {
    try {
      if (pgClient) {
        const { rows } = await pgClient.query('SELECT * FROM bookings ORDER BY created_at DESC');
        return res.json(rows);
      }
      const bookings = readJSON(bookingsPath, []);
      return res.json(bookings);
    } catch (e) {
      logger.error('GET /api/bookings error', e.message);
      res.status(500).json({ error: 'server_error' });
    }
  });

  // POST - create booking (public)
  router.post('/', async (req, res) => {
    try {
      const parsed = BookingCreateSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ 
          error: 'Validation error', 
          details: parsed.error.errors.map(e => ({ field: e.path.join('.'), message: e.message }))
        });
      }

      const payload = parsed.data;

      if (pgClient) {
        const q = `INSERT INTO bookings (id, customer_name, customer_email, customer_phone, booking_type, booking_data, total, payment_status, payment_data, status, created_at)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now()) RETURNING *`;
        const id = `BOOK-${Date.now()}`;
        const values = [id, payload.customerName, payload.customerEmail||null, payload.customerPhone||null, payload.bookingType, JSON.stringify(payload.bookingData||{}), payload.total, payload.paymentStatus, JSON.stringify(payload.paymentData||null), payload.status];
        const { rows } = await pgClient.query(q, values);
        
        // Send confirmation email
        try {
          if (payload.bookingType === 'room') {
            await sendRoomBookingConfirmationEmail(payload.customerEmail, { ...rows[0], id });
          } else {
            await sendHallBookingConfirmationEmail(payload.customerEmail, { ...rows[0], id });
          }
        } catch (emailErr) {
          logger.warn(`Booking confirmation email failed: ${emailErr.message}`);
        }

        return res.status(201).json(rows[0]);
      }

      const bookings = readJSON(bookingsPath, []);
      const id = `BOOK-${Date.now()}`;
      const created = { id, ...payload, createdAt: new Date().toISOString() };
      bookings.unshift(created);
      writeJSON(bookingsPath, bookings);

      // Send confirmation email to customer if email provided
      if (created.customerEmail) {
        try {
          if (payload.bookingType === 'room') {
            await sendRoomBookingConfirmationEmail(created.customerEmail, created);
          } else {
            await sendHallBookingConfirmationEmail(created.customerEmail, created);
          }
        } catch (emailErr) {
          logger.warn(`Booking confirmation email failed: ${emailErr.message}`);
        }
      }

      return res.status(201).json(created);
    } catch (e) {
      logger.error('POST /api/bookings error', e.message);
      res.status(500).json({ error: 'server_error' });
    }
  });

  // PUT - update booking (protected)
  router.put('/:id', authenticate, async (req, res) => {
    try {
      const id = req.params.id;
      const parsed = BookingUpdateSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ 
          error: 'Validation error', 
          details: parsed.error.errors.map(e => ({ field: e.path.join('.'), message: e.message }))
        });
      }

      const payload = parsed.data;
      if (pgClient) {
        const updates = [];
        const values = [];
        let idx = 1;
        
        for (const [k, v] of Object.entries(payload)) {
          if (v !== undefined) {
            if (k === 'status') {
              updates.push(`status = $${idx++}`);
              values.push(v);
            } else if (k === 'paymentStatus') {
              updates.push(`payment_status = $${idx++}`);
              values.push(v);
            } else if (k === 'bookingData') {
              updates.push(`booking_data = $${idx++}`);
              values.push(JSON.stringify(v));
            }
          }
        }
        
        if (updates.length === 0) return res.status(400).json({ error: 'no_updates' });
        const q = `UPDATE bookings SET ${updates.join(',')}, updated_at = now() WHERE id = $${idx} RETURNING *`;
        values.push(id);
        const { rows } = await pgClient.query(q, values);
        if (rows.length === 0) return res.status(404).json({ error: 'not_found' });
        return res.json(rows[0]);
      }

      const bookings = readJSON(bookingsPath, []);
      const idx = bookings.findIndex(b => b.id === id);
      if (idx === -1) return res.status(404).json({ error: 'not_found' });
      bookings[idx] = { ...bookings[idx], ...payload, updatedAt: new Date().toISOString() };
      writeJSON(bookingsPath, bookings);
      return res.json(bookings[idx]);
    } catch (e) {
      logger.error('PUT /api/bookings/:id error', e.message);
      res.status(500).json({ error: 'server_error' });
    }
  });

  return router;
};
