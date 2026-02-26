// Simple M-Pesa service shim.
// If Daraja credentials are provided via environment variables, a real implementation
// can be added here. For now this provides a simulated STK Push response for quick testing.

const initiateStkPush = async ({ phoneNumber, amount, accountName, orderId }, logger) => {
  logger.info({ phoneNumber, amount, orderId }, 'Initiating M-Pesa STK Push (simulated)');

  // If real Daraja integration is desired, check for env vars and implement HTTP calls here.
  if (process.env.MPESA_CONSUMER_KEY && process.env.MPESA_CONSUMER_SECRET) {
    // Real implementation placeholder
    logger.warn('Daraja credentials detected but no implementation present — falling back to simulation');
  }

  // Simulate async STK push flow
  await new Promise((r) => setTimeout(r, 1000));

  const transactionId = `MPESA-${Date.now()}`;
  return {
    transactionId,
    status: 'initiated',
    message: 'STK Push initiated (simulated). User should receive a prompt.'
  };
};

module.exports = { initiateStkPush };
