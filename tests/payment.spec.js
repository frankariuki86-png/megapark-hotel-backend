const { describe, it, expect } = require('vitest');
const paymentService = require('../services/paymentService');

describe('paymentService (mock behavior)', () => {
  it('createPaymentIntent returns mock intent when STRIPE not configured', async () => {
    const logger = { info: () => {}, warn: () => {}, error: () => {} };
    const order = { id: 'order_test_1', totalPrice: 123.45, customerEmail: 'test@example.com', customerName: 'Test' };
    const intent = await paymentService.createPaymentIntent(order, logger);
    expect(intent).toBeDefined();
    expect(intent.id).toBeTruthy();
    expect(intent.clientSecret).toBeTruthy();
    expect(intent.amount).toBe(Math.round(order.totalPrice * 100));
  });

  it('confirmPaymentIntent returns succeeded mock when STRIPE not configured', async () => {
    const logger = { info: () => {}, warn: () => {}, error: () => {} };
    const resp = await paymentService.confirmPaymentIntent('pi_test_123', 'pm_test_123', logger);
    expect(resp).toBeDefined();
    expect(resp.status).toBe('succeeded');
  });
});
