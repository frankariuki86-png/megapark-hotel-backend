import { describe, it, expect, beforeAll } from 'vitest';

const BASE_URL = 'http://localhost:3000';
let accessToken = '';

describe('Orders API', () => {
  beforeAll(async () => {
    const loginRes = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'admin@megapark.com',
        password: 'admin123'
      })
    });
    const loginData = await loginRes.json();
    if (!loginRes.ok || !loginData.accessToken) {
      throw new Error(`Login failed: ${loginRes.status} ${JSON.stringify(loginData)}`);
    }
    accessToken = loginData.accessToken;
  });

  it('should fetch orders', async () => {
    const res = await fetch(`${BASE_URL}/api/orders`, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(Array.isArray(data)).toBe(true);
  });

  it('should create a new order', async () => {
    const newOrder = {
      customerName: 'Test Customer',
      customerEmail: 'test@example.com',
      customerPhone: '+254712345678',
      items: [
        { itemName: 'Nyama Choma', quantity: 2, unitPrice: 850, totalPrice: 1700 }
      ],
      orderType: 'delivery',
      deliveryAddress: '123 Test Street',
      totalAmount: 1700,
      paymentMethod: 'mpesa'
    };

    const res = await fetch(`${BASE_URL}/api/orders`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify(newOrder)
    });

    if (!res.ok) {
      const error = await res.json();
      console.error('Order creation failed:', res.status, JSON.stringify(error));
    }
    expect(res.status).toBe(201);
    const data = await res.json();
    expect(data.customerName).toBe('Test Customer');
    expect(data.status).toBe('pending');
  });

  it('should update order status', async () => {
    // First create an order
    const createRes = await fetch(`${BASE_URL}/api/orders`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        customerName: 'Test User',
        customerEmail: 'test@test.com',
        items: [],
        totalAmount: 100,
        paymentMethod: 'stripe'
      })
    });

    const createdOrder = await createRes.json();
    const orderId = createdOrder.id;

    // Update status
    const updateRes = await fetch(`${BASE_URL}/api/orders/${orderId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify({ status: 'confirmed' })
    });

    expect(updateRes.status).toBe(200);
    const updated = await updateRes.json();
    expect(updated.status).toBe('confirmed');
  });

  it('should require authorization', async () => {
    const res = await fetch(`${BASE_URL}/api/orders`);
    expect(res.status).toBe(401);
  });
});
