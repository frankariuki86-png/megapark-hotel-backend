const { z } = require('zod');

// Menu Item Schemas
const MenuItemCreateSchema = z.object({
  name: z.string().min(1, 'name required').max(255),
  description: z.string().optional(),
  category: z.enum(['appetizers', 'mains', 'sides', 'desserts', 'drinks']).default('mains'),
  price: z.number().min(0, 'price must be >= 0'),
  image: z.string().nullable().optional(),
  preparationTime: z.number().int().min(0).default(15)
});

const MenuItemUpdateSchema = z.object({
  name: z.string().max(255).optional(),
  description: z.string().optional(),
  category: z.enum(['appetizers', 'mains', 'sides', 'desserts', 'drinks']).optional(),
  price: z.number().min(0).optional(),
  image: z.string().nullable().optional(),
  availability: z.boolean().optional(),
  preparationTime: z.number().int().min(0).optional()
}).refine(obj => Object.keys(obj).length > 0, 'At least one field required');

// Order Schemas
const OrderItemSchema = z.object({
  itemName: z.string(),
  quantity: z.number().int().min(1),
  unitPrice: z.number().min(0),
  totalPrice: z.number().min(0)
});

const OrderCreateSchema = z.object({
  customerName: z.string().min(1, 'customer name required').max(255),
  customerEmail: z.string().email().optional(),
  customerPhone: z.string().optional(),
  orderType: z.enum(['delivery', 'dine-in', 'pickup']).default('dine-in'),
  orderDate: z.string().datetime().optional(),
  deliveryDate: z.string().nullable().optional(),
  deliveryAddress: z.object({
    fullName: z.string().min(1),
    phone: z.string().min(5),
    county: z.string().min(1),
    town: z.string().min(1),
    street: z.string().min(1),
    building: z.string().optional().nullable(),
    instructions: z.string().optional().nullable()
  }).nullable().optional(),
  items: z.array(OrderItemSchema).optional(),
  subtotal: z.number().min(0).optional().default(0),
  deliveryFee: z.number().min(0).default(0),
  tax: z.number().min(0).default(0),
  totalAmount: z.number().min(0),
  status: z.enum(['pending', 'confirmed', 'preparing', 'ready', 'delivered', 'cancelled']).default('pending'),
  paymentStatus: z.enum(['pending', 'paid', 'failed', 'refunded']).default('pending'),
  paymentMethod: z.string().optional()
});

const OrderUpdateSchema = z.object({
  status: z.enum(['pending', 'confirmed', 'preparing', 'ready', 'delivered', 'cancelled']).optional(),
  paymentStatus: z.enum(['pending', 'paid', 'failed', 'refunded']).optional(),
  items: z.array(OrderItemSchema).optional()
}).refine(obj => Object.keys(obj).length > 0, 'At least one field required');

// Password validation - requires min 8 chars, uppercase, lowercase, number
const passwordValidation = z.string()
  .min(8, 'Password must be at least 8 characters')
  .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
  .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
  .regex(/[0-9]/, 'Password must contain at least one number');

// Auth Schema
const LoginSchema = z.object({
  email: z.string().email('Invalid email'),
  password: z.string().min(1, 'Password required')
});

// Registration Schema with strong password requirements
const RegisterSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: passwordValidation,
  firstName: z.string().min(1, 'First name required').max(50),
  lastName: z.string().min(1, 'Last name required').max(50),
  phone: z.string().regex(/^\+?[0-9\s\-()]+$/, 'Invalid phone number').optional()
});

// Payment Schema
const PaymentIntentSchema = z.object({
  id: z.string().optional(),
  totalPrice: z.number().min(0.01, 'Amount must be > 0'),
  customerName: z.string().min(1).max(255).optional(),
  customerEmail: z.string().email().optional(),
  description: z.string().optional(),
  bookingId: z.string().optional()
});


// Admin User Schemas
const AdminUserCreateSchema = z.object({
  email: z.string().email('Invalid email'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  name: z.string().min(1, 'Name required').max(255),
  role: z.enum(['admin', 'staff']).default('staff')
});

const AdminUserUpdateSchema = z.object({
  name: z.string().max(255).optional(),
  role: z.enum(['admin', 'staff']).optional(),
  isActive: z.boolean().optional()
}).refine(obj => Object.keys(obj).length > 0, 'At least one field required');

// Hall Schemas
const HallCreateSchema = z.object({
  name: z.string().min(1, 'name required').max(255),
  description: z.string().optional(),
  capacity: z.number().int().min(1, 'capacity must be > 0'),
  pricePerDay: z.number().min(0, 'price must be >= 0'),
  images: z.array(z.string()).optional().default([]),
  amenities: z.array(z.string()).optional().default([]),
  availability: z.boolean().optional().default(true)
});

const HallUpdateSchema = z.object({
  name: z.string().max(255).optional(),
  description: z.string().optional(),
  capacity: z.number().int().min(1).optional(),
  pricePerDay: z.number().min(0).optional(),
  images: z.array(z.string()).optional(),
  amenities: z.array(z.string()).optional(),
  availability: z.boolean().optional()
}).refine(obj => Object.keys(obj).length > 0, 'At least one field required');

// Booking Schemas
const BookingCreateSchema = z.object({
  customerName: z.string().min(1, 'Customer name required').max(255),
  customerEmail: z.string().email('Invalid email').optional(),
  customerPhone: z.string().regex(/^\+?[0-9\s\-()]+$/, 'Invalid phone number').optional(),
  bookingType: z.enum(['room', 'hall']).default('room'),
  bookingData: z.object({
    roomId: z.string().optional(),
    hallId: z.string().optional(), 
    checkIn: z.string().datetime().optional(),
    checkOut: z.string().datetime().optional(),
    guests: z.number().int().min(1).optional(),
    specialRequests: z.string().optional()
  }).optional(),
  total: z.number().min(0),
  paymentStatus: z.enum(['pending', 'paid', 'failed', 'refunded']).default('pending'),
  paymentData: z.record(z.any()).optional(),
  status: z.enum(['booked', 'confirmed', 'cancelled', 'completed']).default('booked')
});

const BookingUpdateSchema = z.object({
  status: z.enum(['booked', 'confirmed', 'cancelled', 'completed']).optional(),
  paymentStatus: z.enum(['pending', 'paid', 'failed', 'refunded']).optional(),
  bookingData: z.record(z.any()).optional()
}).refine(obj => Object.keys(obj).length > 0, 'At least one field required');

// Hall Quote Schemas
const HallQuoteCreateSchema = z.object({
  customerName: z.string().min(1, 'Customer name required').max(255),
  customerEmail: z.string().email('Invalid email'),
  customerPhone: z.string().regex(/^\+?[0-9\s\-()]+$/, 'Invalid phone number'),
  hallId: z.string().optional(),
  hallName: z.string().min(1, 'Hall name required').optional(),
  eventDate: z.string().datetime('Invalid date'),
  eventType: z.string().min(1, 'Event type required').max(100),
  guestCount: z.number().int().min(1, 'Guest count must be at least 1'),
  specialRequirements: z.string().optional(),
  budget: z.number().min(0).optional(),
  status: z.enum(['pending', 'responded', 'quoted', 'accepted', 'rejected']).default('pending')
});

const HallQuoteUpdateSchema = z.object({
  status: z.enum(['pending', 'responded', 'quoted', 'accepted', 'rejected']).optional(),
  quotedPrice: z.number().min(0).optional(),
  notes: z.string().optional()
}).refine(obj => Object.keys(obj).length > 0, 'At least one field required');

// Room Schemas
const RoomCreateSchema = z.object({
  roomNumber: z.string().min(1, 'room number required').max(50),
  name: z.string().min(1, 'name required').max(255),
  type: z.enum(['standard', 'double', 'deluxe', 'suite', 'executive']).default('standard'),
  description: z.string().optional(),
  pricePerNight: z.number().min(0, 'price must be >= 0'),
  images: z.array(z.string()).optional().default([]),
  amenities: z.array(z.string()).optional().default([]),
  capacity: z.number().int().min(1).optional().default(2),
  availability: z.boolean().optional().default(true)
});

const RoomUpdateSchema = z.object({
  roomNumber: z.string().max(50).optional(),
  name: z.string().max(255).optional(),
  type: z.enum(['standard', 'double', 'deluxe', 'suite', 'executive']).optional(),
  description: z.string().optional(),
  pricePerNight: z.number().min(0).optional(),
  images: z.array(z.string()).optional(),
  amenities: z.array(z.string()).optional(),
  capacity: z.number().int().min(1).optional(),
  availability: z.boolean().optional()
}).refine(obj => Object.keys(obj).length > 0, 'At least one field required');

module.exports = {
  MenuItemCreateSchema,
  MenuItemUpdateSchema,
  OrderCreateSchema,
  OrderUpdateSchema,
  LoginSchema,
  RegisterSchema,
  PaymentIntentSchema,
  AdminUserCreateSchema,
  AdminUserUpdateSchema,
  HallCreateSchema,
  HallUpdateSchema,
  RoomCreateSchema,
  RoomUpdateSchema,
  BookingCreateSchema,
  BookingUpdateSchema,
  HallQuoteCreateSchema,
  HallQuoteUpdateSchema,
  passwordValidation
};
