import { describe, it, expect, beforeAll } from 'vitest';

const BASE_URL = 'http://localhost:3000';
let accessToken = '';

describe('Menu API', () => {
  beforeAll(async () => {
    // Get auth token
    const loginRes = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'admin@megapark.com',
        password: 'admin123'
      })
    });
    const loginData = await loginRes.json();
    accessToken = loginData.accessToken;
  });

  it('should fetch menu items', async () => {
    const res = await fetch(`${BASE_URL}/api/menu`, {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(Array.isArray(data)).toBe(true);
  });

  it('should create a new menu item', async () => {
    const newItem = {
      name: 'Test Dish',
      description: 'Test Description',
      category: 'mains',
      price: 500,
      availability: true
    };

    const res = await fetch(`${BASE_URL}/api/menu`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify(newItem)
    });

    expect(res.status).toBe(201);
    const data = await res.json();
    expect(data.name).toBe('Test Dish');
    expect(data.price).toBe(500);
  });

  it('should update a menu item', async () => {
    // First create an item
    const createRes = await fetch(`${BASE_URL}/api/menu`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        name: 'Test Item',
        price: 100,
        category: 'drinks',
        availability: true
      })
    });

    const createdItem = await createRes.json();
    const itemId = createdItem.id;

    // Update it
    const updateRes = await fetch(`${BASE_URL}/api/menu/${itemId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify({ price: 150 })
    });

    expect(updateRes.status).toBe(200);
    const updated = await updateRes.json();
    expect(updated.price).toBe(150);
  });

  it('should require authorization for menu operations', async () => {
    const res = await fetch(`${BASE_URL}/api/menu`);
    expect(res.status).toBe(401);
  });
});
