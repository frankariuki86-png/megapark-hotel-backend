const { Client } = require('pg');
require('dotenv').config();

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('❌ DATABASE_URL not set. Cannot run seed.');
  process.exit(1);
}

const seedData = {
  menuItems: [
    {
      name: 'Nyama Choma',
      description: 'Grilled meat with local spices and vegetables',
      category: 'mains',
      price: 850,
      image: null,
      availability: true,
      preparationTime: 30
    },
    {
      name: 'Ugali with Sukuma Wiki',
      description: 'Traditional maize meal with sautéed greens',
      category: 'mains',
      price: 350,
      image: null,
      availability: true,
      preparationTime: 15
    },
    {
      name: 'Samosas',
      description: 'Crispy pastry with meat or vegetable filling',
      category: 'appetizers',
      price: 200,
      image: null,
      availability: true,
      preparationTime: 10
    },
    {
      name: 'Chapati',
      description: 'Soft flatbread',
      category: 'sides',
      price: 100,
      image: null,
      availability: true,
      preparationTime: 8
    },
    {
      name: 'Mango Juice',
      description: 'Fresh mango juice',
      category: 'drinks',
      price: 250,
      image: null,
      availability: true,
      preparationTime: 5
    }
  ],
  orders: [
    {
      customerName: 'Alice Johnson',
      customerEmail: 'alice@example.com',
      customerPhone: '+254712111222',
      orderType: 'delivery',
      orderDate: new Date('2024-02-11T10:30:00'),
      deliveryDate: '2024-02-11',
      deliveryAddress: '123 Main Street, Nairobi',
      items: JSON.stringify([
        { itemName: 'Nyama Choma', quantity: 2, unitPrice: 850, totalPrice: 1700 },
        { itemName: 'Chapati', quantity: 2, unitPrice: 100, totalPrice: 200 }
      ]),
      subtotal: 1900,
      deliveryFee: 200,
      tax: 228,
      totalAmount: 2328,
      status: 'preparing',
      paymentStatus: 'paid',
      paymentMethod: 'mpesa'
    },
    {
      customerName: 'Bob Smith',
      customerEmail: 'bob@example.com',
      customerPhone: '+254798333444',
      orderType: 'dine-in',
      orderDate: new Date('2024-02-11T14:45:00'),
      deliveryDate: null,
      deliveryAddress: null,
      items: JSON.stringify([
        { itemName: 'Samosas', quantity: 6, unitPrice: 200, totalPrice: 1200 },
        { itemName: 'Mango Juice', quantity: 2, unitPrice: 250, totalPrice: 500 }
      ]),
      subtotal: 1700,
      deliveryFee: 0,
      tax: 204,
      totalAmount: 1904,
      status: 'ready',
      paymentStatus: 'paid',
      paymentMethod: 'stripe'
    }
  ]
};

const seed = async () => {
  const client = new Client({ connectionString: DATABASE_URL });
  try {
    await client.connect();
    console.log('✓ Connected to database');

    // Truncate existing data
    console.log('\nTruncating existing data...');
    await client.query('DELETE FROM food_orders');
    await client.query('DELETE FROM menu_items');

    // Seed menu items
    console.log('Seeding menu items...');
    for (const item of seedData.menuItems) {
      const q = `INSERT INTO menu_items (name, description, category, price, image, availability, preparation_time)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)`;
      await client.query(q, [
        item.name,
        item.description,
        item.category,
        item.price,
        item.image,
        item.availability,
        item.preparationTime
      ]);
    }
    console.log(`✓ Seeded ${seedData.menuItems.length} menu items`);

    // Seed orders
    console.log('Seeding food orders...');
    for (const order of seedData.orders) {
      const q = `INSERT INTO food_orders (customer_name, customer_email, customer_phone, order_type, order_date, delivery_date, delivery_address, items, subtotal, delivery_fee, tax, total_amount, status, payment_status, payment_method)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`;
      await client.query(q, [
        order.customerName,
        order.customerEmail,
        order.customerPhone,
        order.orderType,
        order.orderDate,
        order.deliveryDate,
        order.deliveryAddress,
        order.items,
        order.subtotal,
        order.deliveryFee,
        order.tax,
        order.totalAmount,
        order.status,
        order.paymentStatus,
        order.paymentMethod
      ]);
    }
    console.log(`✓ Seeded ${seedData.orders.length} food orders`);

    console.log('\n✓ Seed completed successfully');
  } catch (e) {
    console.error('❌ Seed error:', e.message);
    process.exit(1);
  } finally {
    await client.end();
  }
};

seed();
