const express = require('express');
const router = express.Router();
const { HallQuoteCreateSchema } = require('../validators/schemas');
const { sendEmail } = require('../services/emailService');

module.exports = ({ logger }) => {
  // POST /api/halls/quote - submit a hall quote request (public)
  router.post('/', async (req, res) => {
    try {
      const parsed = HallQuoteCreateSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ 
          error: 'Validation error', 
          details: parsed.error.errors.map(e => ({ field: e.path.join('.'), message: e.message }))
        });
      }

      const payload = parsed.data;

      // Create quote record in system
      const quoteId = `QUOTE-${Date.now()}`;
      const quote = {
        id: quoteId,
        ...payload,
        createdAt: new Date().toISOString(),
        status: 'pending'
      };

      // Send confirmation email to customer
      const customerEmailContent = {
        subject: 'Hall Quote Request Received',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px;">
            <h2>Thank You! Quote Request Received</h2>
            <p>Hi ${payload.customerName},</p>
            <p>We received your hall quote request for your ${payload.eventType} event on ${new Date(payload.eventDate).toLocaleDateString()}.</p>
            <p><strong>Request Details:</strong></p>
            <ul>
              <li>Event Type: ${payload.eventType}</li>
              <li>Expected Guests: ${payload.guestCount}</li>
              <li>Event Date: ${new Date(payload.eventDate).toLocaleDateString()}</li>
              ${payload.budget ? `<li>Budget: KES ${payload.budget.toLocaleString()}</li>` : ''}
            </ul>
            <p>Our sales team will review your request and send you a detailed quote within 24 hours.</p>
            <p>If you have any immediate questions, feel free to contact us at:</p>
            <p><strong>Phone:</strong> ${process.env.ADMIN_PHONE || '+254711768878'}<br/>
            <strong>Email:</strong> ${process.env.SALES_EMAIL || 'sales@megapark-hotel.com'}</p>
            <hr/>
            <p style="color: #666; font-size: 12px;">MegaPark Hotel | Events &amp; Functions</p>
          </div>
        `
      };

      try {
        await sendEmail(payload.customerEmail, 'quoteConfirmation', quote);
      } catch (emailErr) {
        logger.warn(`Quote confirmation email failed: ${emailErr.message}`);
      }

      // Send notification to admin/sales team
      const adminEmail = process.env.SALES_EMAIL || process.env.ADMIN_EMAIL || 'sales@megapark-hotel.com';
      const adminEmailContent = {
        subject: `NEW: Hall Quote Request from ${payload.customerName}`,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px;">
            <h2>New Hall Quote Request</h2>
            <p><strong>Quote ID:</strong> ${quoteId}</p>
            <h3>Customer Information:</h3>
            <ul>
              <li>Name: ${payload.customerName}</li>
              <li>Email: ${payload.customerEmail}</li>
              <li>Phone: ${payload.customerPhone}</li>
            </ul>
            <h3>Event Details:</h3>
            <ul>
              <li>Event Type: ${payload.eventType}</li>
              <li>Requested Hall: ${payload.hallName || 'Any'}</li>
              <li>Event Date: ${new Date(payload.eventDate).toLocaleDateString()}</li>
              <li>Guest Count: ${payload.guestCount}</li>
              ${payload.budget ? `<li>Budget: KES ${payload.budget.toLocaleString()}</li>` : ''}
              ${payload.specialRequirements ? `<li>Special Requirements: ${payload.specialRequirements}</li>` : ''}
            </ul>
            <p>Please review and send a quote to the customer within 24 hours.</p>
          </div>
        `
      };

      try {
        await sendEmail(adminEmail, 'adminAlert', adminEmailContent);
      } catch (emailErr) {
        logger.warn(`Sales notification email failed: ${emailErr.message}`);
      }

      logger.info({ quoteId, customer: payload.customerEmail }, 'Hall quote request received');

      return res.status(201).json({ 
        ok: true, 
        message: 'Quote request received. We will send you a detailed quote shortly.',
        quote 
      });
    } catch (e) {
      logger.error('POST /api/halls/quote error', e.message);
      return res.status(500).json({ error: 'server_error' });
    }
  });

  return router;
};
