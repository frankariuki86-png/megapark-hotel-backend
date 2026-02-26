const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY || 'sk_test_stub');

/**
 * Create payment intent for order
 * @param {object} order - Order object with totalPrice, customerEmail, etc.
 * @param {object} logger - Pino logger
 */
const createPaymentIntent = async (order, logger, metadata = {}) => {
  try {
    if (!process.env.STRIPE_SECRET_KEY) {
      logger.warn('Stripe not configured, returning mock intent');
      return {
        id: `pi_test_${Date.now()}`,
        clientSecret: `pi_test_${Date.now()}_secret_test`,
        status: 'requires_payment_method',
        amount: Math.round(order.totalPrice * 100), // Convert to cents
        currency: 'usd',
        metadata: metadata || {}
      };
    }

    const intent = await stripe.paymentIntents.create({
      amount: Math.round(order.totalPrice * 100), // Stripe uses cents
      currency: 'usd',
      payment_method_types: ['card'],
      description: `Order #${order.id || ''}`,
      metadata: Object.assign({ orderId: order.id, customerName: order.customerName, customerEmail: order.customerEmail }, metadata || {}),
      receipt_email: order.customerEmail
    });

    logger.info({ orderId: order.id, intentId: intent.id }, 'Payment intent created');
    return intent;
  } catch (error) {
    logger.error({ orderId: order.id, error: error.message }, 'Payment intent creation failed');
    throw error;
  }
};

/**
 * Confirm payment intent
 * @param {string} intentId - Payment intent ID
 * @param {string} paymentMethodId - Payment method ID
 * @param {object} logger - Pino logger
 */
const confirmPaymentIntent = async (intentId, paymentMethodId, logger) => {
  try {
    if (!process.env.STRIPE_SECRET_KEY) {
      logger.warn('Stripe not configured, returning mock confirmation');
      return {
        id: intentId,
        status: 'succeeded',
        charges: { data: [{ id: `ch_test_${Date.now()}` }] }
      };
    }

    const intent = await stripe.paymentIntents.confirm(intentId, {
      payment_method: paymentMethodId
    });

    if (intent.status === 'succeeded') {
      logger.info({ intentId: intent.id, chargeId: intent.charges.data[0]?.id }, 'Payment succeeded');
    } else if (intent.status === 'requires_action') {
      logger.info({ intentId }, '3D Secure authentication required');
    }

    return intent;
  } catch (error) {
    logger.error({ intentId, error: error.message }, 'Payment confirmation failed');
    throw error;
  }
};

/**
 * Retrieve payment intent
 * @param {string} intentId - Payment intent ID
 * @param {object} logger - Pino logger
 */
const getPaymentIntent = async (intentId, logger) => {
  try {
    if (!process.env.STRIPE_SECRET_KEY) {
      return { id: intentId, status: 'succeeded' };
    }

    return await stripe.paymentIntents.retrieve(intentId);
  } catch (error) {
    logger.error({ intentId, error: error.message }, 'Failed to retrieve payment intent');
    throw error;
  }
};

/**
 * Create customer (for saved payment methods)
 * @param {object} user - User object
 * @param {object} logger - Pino logger
 */
const createCustomer = async (user, logger) => {
  try {
    if (!process.env.STRIPE_SECRET_KEY) {
      return { id: `cus_test_${user.id}` };
    }

    const customer = await stripe.customers.create({
      email: user.email,
      name: user.name,
      metadata: { userId: user.id }
    });

    logger.info({ customerId: customer.id, userId: user.id }, 'Stripe customer created');
    return customer;
  } catch (error) {
    logger.error({ userId: user.id, error: error.message }, 'Stripe customer creation failed');
    throw error;
  }
};

/**
 * Create subscription
 * @param {string} customerId - Stripe customer ID
 * @param {string} priceId - Stripe price ID
 * @param {object} logger - Pino logger
 */
const createSubscription = async (customerId, priceId, logger) => {
  try {
    if (!process.env.STRIPE_SECRET_KEY) {
      return { id: `sub_test_${Date.now()}`, status: 'active' };
    }

    const subscription = await stripe.subscriptions.create({
      customer: customerId,
      items: [{ price: priceId }],
      payment_behavior: 'default_incomplete',
      expand: ['latest_invoice.payment_intent']
    });

    logger.info({ customerId, subscriptionId: subscription.id }, 'Subscription created');
    return subscription;
  } catch (error) {
    logger.error({ customerId, error: error.message }, 'Subscription creation failed');
    throw error;
  }
};

/**
 * Handle webhook event
 * @param {object} event - Stripe webhook event
 * @param {object} logger - Pino logger
 */
const handleWebhookEvent = async (event, logger) => {
  try {
    switch (event.type) {
      case 'payment_intent.succeeded':
        logger.info({ intentId: event.data.object.id }, 'Payment intent succeeded');
        return { handled: true, action: 'payment_succeeded' };

      case 'payment_intent.payment_failed':
        logger.error({ intentId: event.data.object.id }, 'Payment intent failed');
        return { handled: true, action: 'payment_failed' };

      case 'charge.refunded':
        logger.info({ chargeId: event.data.object.id }, 'Charge refunded');
        return { handled: true, action: 'charge_refunded' };

      case 'customer.subscription.deleted':
        logger.info({ subscriptionId: event.data.object.id }, 'Subscription cancelled');
        return { handled: true, action: 'subscription_cancelled' };

      default:
        logger.debug({ eventType: event.type }, 'Webhook event received');
        return { handled: false };
    }
  } catch (error) {
    logger.error({ eventId: event.id, error: error.message }, 'Webhook handling failed');
    throw error;
  }
};

/**
 * Verify webhook signature
 * @param {string} payload - Raw request body
 * @param {string} signature - Stripe signature header
 */
const verifyWebhookSignature = (payload, signature) => {
  if (!process.env.STRIPE_WEBHOOK_SECRET) {
    return true; // Skip verification if not configured
  }

  try {
    const event = stripe.webhooks.constructEvent(
      payload,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET
    );
    return event;
  } catch (error) {
    throw new Error(`Webhook signature verification failed: ${error.message}`);
  }
};

module.exports = {
  createPaymentIntent,
  confirmPaymentIntent,
  getPaymentIntent,
  createCustomer,
  createSubscription,
  handleWebhookEvent,
  verifyWebhookSignature
};
