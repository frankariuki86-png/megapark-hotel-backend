const nodemailer = require('nodemailer');

// Initialize email transporter
let transporter = null;

const initializeTransporter = () => {
  // Check if using SendGrid
  if (process.env.SENDGRID_API_KEY) {
    const sgTransport = require('nodemailer-sendgrid-transport');
    return nodemailer.createTransport(
      sgTransport({
        auth: { api_key: process.env.SENDGRID_API_KEY }
      })
    );
  }

  // Use SMTP (Gmail, custom, etc.)
  if (process.env.EMAIL_HOST) {
    return nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: parseInt(process.env.EMAIL_PORT || '587'),
      secure: process.env.EMAIL_SECURE === 'true', // true for 465, false for other ports
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });
  }

  // Fallback: dev mode (ethereal)
  return null;
};

const getTransporter = async () => {
  if (!transporter) {
    transporter = initializeTransporter();
    
    // For dev: create test account
    if (!transporter) {
      const testAccount = await nodemailer.createTestAccount();
      transporter = nodemailer.createTransport({
        host: 'smtp.ethereal.email',
        port: 587,
        secure: false,
        auth: { user: testAccount.user, pass: testAccount.pass }
      });
    }
  }
  return transporter;
};

// Email Templates
const templates = {
  welcome: (data) => ({
    subject: 'Welcome to MegaPark Hotel & Resort',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #0b7546;">Welcome to MegaPark Hotel & Resort! 🏨</h2>
        <p>Hi ${data.name || 'Guest'},</p>
        <p>Thank you for creating an account with us! We're excited to welcome you.</p>
        <div style="background: linear-gradient(135deg, #0b7546 0%, #06324a 100%); color: white; padding: 20px; border-radius: 8px; margin: 20px 0;">
          <h3>What you can do now:</h3>
          <ul>
            <li>✓ Order delicious food from our restaurant</li>
            <li>✓ Book comfortable rooms for your stay</li>
            <li>✓ Request quotes for events and functions</li>
            <li>✓ Track your orders and bookings in real-time</li>
          </ul>
        </div>
        <p>Your account is ready to use. Log in with your credentials to get started!</p>
        <p>If you have any questions or need assistance, our customer service team is here to help.</p>
        <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;"/>
        <p><strong>Contact Us:</strong><br/>
        Email: support@megapark-hotel.com<br/>
        Phone: +254711768878</p>
        <p style="color: #666; font-size: 12px; margin-top: 30px;">MegaPark Hotel & Resort | Nairobi, Kenya</p>
      </div>
    `
  }),

  paymentConfirmation: (data) => ({
    subject: `Payment Confirmation - Transaction #${data.payment.id || 'PENDING'}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px;">
        <h2>Payment Confirmation</h2>
        <p>Hi ${data.payment.customerName || 'Guest'},</p>
        <p>Your payment has been received successfully!</p>
        <div style="background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 15px 0;">
          <strong>Transaction ID:</strong> ${data.payment.id}<br/>
          <strong>Amount:</strong> KES ${data.payment.amount?.toLocaleString() || '0.00'}<br/>
          <strong>Payment Method:</strong> ${data.payment.method || 'Online'}<br/>
          <strong>Date:</strong> ${new Date().toLocaleDateString()}<br/>
          <strong>Status:</strong> <span style="color: green; font-weight: bold;">✓ Confirmed</span>
        </div>
        <p>You will receive further updates about your order/booking shortly.</p>
        <p>Thank you for choosing MegaPark Hotel & Resort!</p>
        <hr/>
        <p style="color: #666; font-size: 12px;">MegaPark Hotel | Customer Service</p>
      </div>
    `
  }),

  orderConfirmation: (order, user) => ({
    subject: `Order Confirmation #${order.id}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px;">
        <h2>Order Confirmation</h2>
        <p>Hi ${order.customerName || user?.name || 'Guest'},</p>
        <p>Thank you for your order! Here are the details:</p>
        <div style="background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 15px 0;">
          <strong>Order ID:</strong> ${order.id}<br/>
          <strong>Date:</strong> ${new Date(order.createdAt).toLocaleDateString()}<br/>
          <strong>Status:</strong> ${order.status || 'pending'}<br/>
          <strong>Total:</strong> $${order.totalPrice?.toFixed(2) || '0.00'}
        </div>
        <h3>Order Items:</h3>
        <ul>
          ${order.items?.map(item => `
            <li>${item.name || 'Item'} - $${item.price?.toFixed(2) || '0.00'} x ${item.quantity || 1}</li>
          `).join('') || '<li>No items</li>'}
        </ul>
        ${order.specialRequests ? `<p><strong>Special Requests:</strong> ${order.specialRequests}</p>` : ''}
        <p>We'll notify you when your order is being prepared.</p>
        <hr/>
        <p style="color: #666; font-size: 12px;">MegaPark Hotel | Customer Service</p>
      </div>
    `
  }),

  bookingConfirmation: (booking, type = 'room') => ({
    subject: `${type.charAt(0).toUpperCase() + type.slice(1)} Booking Confirmation #${booking.id}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px;">
        <h2>${type.charAt(0).toUpperCase() + type.slice(1)} Booking Confirmation</h2>
        <p>Hi ${booking.customerName},</p>
        <p>Your ${type} booking has been confirmed!</p>
        <div style="background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 15px 0;">
          <strong>Booking ID:</strong> ${booking.id}<br/>
          <strong>Type:</strong> ${type}<br/>
          <strong>Check-in:</strong> ${new Date(booking.checkIn).toLocaleDateString()}<br/>
          <strong>Check-out:</strong> ${new Date(booking.checkOut).toLocaleDateString()}<br/>
          <strong>Total Cost:</strong> $${booking.totalPrice?.toFixed(2) || '0.00'}
        </div>
        <p>Please arrive 30 minutes before your scheduled time.</p>
        <p>If you have any questions, contact us at support@megapark-hotel.com</p>
        <hr/>
        <p style="color: #666; font-size: 12px;">MegaPark Hotel | Reservations</p>
      </div>
    `
  }),

  passwordReset: (user, resetLink) => ({
    subject: 'Password Reset Request',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px;">
        <h2>Password Reset Request</h2>
        <p>Hi ${user.name || user.email},</p>
        <p>We received a request to reset your password. Click the link below to proceed:</p>
        <p>
          <a href="${resetLink}" style="display: inline-block; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px;">
            Reset Password
          </a>
        </p>
        <p style="color: #666;">This link expires in 1 hour.</p>
        <p>If you didn't request this, you can ignore this email.</p>
        <hr/>
        <p style="color: #666; font-size: 12px;">MegaPark Hotel | Security</p>
      </div>
    `
  }),

  adminAlert: (subject, message, data = {}) => ({
    subject: `[ADMIN ALERT] ${subject}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px;">
        <h2 style="color: #d9534f;">Admin Alert</h2>
        <p><strong>${subject}</strong></p>
        <p>${message}</p>
        ${Object.keys(data).length > 0 ? `
          <div style="background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 15px 0;">
            ${Object.entries(data).map(([key, value]) => 
              `<p><strong>${key}:</strong> ${JSON.stringify(value)}</p>`
            ).join('')}
          </div>
        ` : ''}
        <hr/>
        <p style="color: #666; font-size: 12px;">MegaPark Hotel | Automated Alert System</p>
      </div>
    `
  }),

  hallQuoteRequest: (request) => ({
      subject: `New Hall Quote Request: ${request.hallName || 'Hall'}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px;">
          <h2>New Hall Quote Request</h2>
          <p><strong>Hall:</strong> ${request.hallName || 'N/A'}</p>
          <p><strong>Package:</strong> ${request.packageName || 'N/A'}</p>
          <p><strong>Event Date:</strong> ${request.eventDate || 'N/A'} ${request.eventTime || ''}</p>
          <p><strong>Guests:</strong> ${request.guestCount || 'N/A'}</p>
          <h3>Contact Details</h3>
          <p><strong>Name:</strong> ${request.contactName || 'N/A'}</p>
          <p><strong>Email:</strong> ${request.contactEmail || 'N/A'}</p>
          <p><strong>Phone:</strong> ${request.contactPhone || 'N/A'}</p>
          ${request.notes ? `<h4>Notes</h4><p>${request.notes}</p>` : ''}
          <hr/>
          <p style="color: #666; font-size: 12px;">MegaPark Hotel | Quote Requests</p>
        </div>
      `
    })
};

/**
 * Send email
 * @param {string} to - Recipient email
 * @param {string} templateName - Template name (orderConfirmation, bookingConfirmation, etc.)
 * @param {object} data - Data for template
 * @param {object} logger - Pino logger instance
 */
const sendEmail = async (to, templateName, data, logger) => {
  try {
    const mailer = await getTransporter();
    if (!mailer) {
      logger.warn('Email service not configured, skipping email send');
      return { sent: false, reason: 'Not configured' };
    }

    // Get template
    const template = templates[templateName];
    if (!template) {
      throw new Error(`Unknown template: ${templateName}`);
    }

    // Render template
    const emailContent = typeof template === 'function' ? template(data) : template;

    // Send email
    const info = await mailer.sendMail({
      from: process.env.EMAIL_FROM || 'noreply@megapark-hotel.com',
      to,
      subject: emailContent.subject,
      html: emailContent.html,
      text: emailContent.text || null
    });

    logger.info({ to, template: templateName, messageId: info.messageId }, 'Email sent');
    
    // For dev: log preview URL
    if (info.response?.includes('ethereal')) {
      logger.info({ previewUrl: nodemailer.getTestMessageUrl(info) }, 'Email preview URL');
    }

    return { sent: true, messageId: info.messageId };
  } catch (error) {
    logger.error({ to, template: templateName, error: error.message }, 'Email send failed');
    return { sent: false, error: error.message };
  }
};

module.exports = {
  sendEmail,
  templates,
  initializeTransporter,
  // Convenience functions for common emails
  sendWelcomeEmail: async (email, name) => {
    return sendEmail(email, 'welcome', { name });
  },
  sendOrderConfirmationEmail: async (email, order, user) => {
    return sendEmail(email, 'orderConfirmation', { order, user });
  },
  sendRoomBookingConfirmationEmail: async (email, booking) => {
    return sendEmail(email, 'bookingConfirmation', { booking, type: 'room' });
  },
  sendHallBookingConfirmationEmail: async (email, booking) => {
    return sendEmail(email, 'bookingConfirmation', { booking, type: 'hall' });
  },
  sendPaymentConfirmationEmail: async (email, payment) => {
    return sendEmail(email, 'paymentConfirmation', { payment });
  }
};
