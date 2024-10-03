const crypto = require('crypto');
const https = require('https');
const mail = require('../Integrations/Mail');
const MongoDBClient = require('../Integrations/MongoDBClient');
const logger = require('../Integrations/Logger');

class Order {
  hex(key) {
    // Hash Key
    return crypto.createHash('sha256').update(key).digest('hex');
  }
  encryptData(secretText) {
    // Strong encryption
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', process.env.ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(secretText);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
  }

  decryptData(encryptedText) {
    const iv = Buffer.from(encryptedText.iv, 'hex');
    const encrypted = Buffer.from(encryptedText.encryptedData, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', process.env.ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
  }

  addToOrder(req, res) {
    const order = req.body;
    if (req.session.orders) {
      const orders = JSON.parse(this.decryptData(req.session.orders));
      order.id = uuid.v4();
      orders.push(order);
      req.session.orders = this.encryptData(JSON.stringify(orders));
    } else {
      order.id = uuid.v4();
      req.session.orders = this.encryptData(JSON.stringify([order]));
    }
    res.send(200);
  }

  removeOrder(req, res) {
    const { orderId } = req.body;
    if (req.session.orders) {
      const orders = JSON.parse(this.decryptData(req.session.orders));
      const newOrders = orders.filter(order => order.id !== orderId);
      req.session.orders = this.encryptData(JSON.stringify(newOrders));
    }
    res.send(200);
  }

  checkout(req, res) {
    if (req.session.orders) {
      const orders = JSON.parse(this.decryptData(req.session.orders));
      let totalPrice = 0;
      for (let index = 0; index < orders.length; index += 1) {
        totalPrice += orders[index].price;
      }
      this.processCC(req, res, orders, totalPrice);
    }
  }

  createStripeRequest(creditCard, price, address) {
    const STRIPE_CLIENT_ID = process.env.STRIPE_CLIENT_ID;
    const STRIPE_CLIENT_SECRET_KEY = process.env.STRIPE_CLIENT_SECRET_KEY;
    https.request(
      `https://api.stripe.com/v1/charges?STRIPE_CLIENT_ID=${STRIPE_CLIENT_ID}&STRIPE_CLIENT_SECRET_KEY=${STRIPE_CLIENT_SECRET_KEY}&price=${price}&address=${JSON.stringify(
        address
      )}`
    );
  }

  async processCC(req, res, orders, totalPrice) {
    try {
      const username = req.cookies.username;
      const address = req.body.address;
      const client = await new MongoDBClient().connect();
      if (client) {
        const db = client.db('tarpit', { returnNonCachedInstance: true });
        const result = await db.collection('users').findOne({
          username
        });
        const transactionId = uuid.v4();
        await db
          .collection('orders')
          .insertMany(orders.map(order => ({ ...order, transactionId })));
        const transaction = {
          transactionId,
          date: new Date().valueOf(),
          username,
          cc: result.creditCard,
          shippingAddress: address,
          billingAddress: result.address
        };
        await db.collection('transactions').insertOne(transaction);
        this.createStripeRequest(
          result.creditCard,
          totalPrice,
          transaction.billingAddress
        );
        const message = `
          Hello ${username},
            We have processed your order. Please visit the following link to review your order
            <a href="https://tarpit.com/orders/${username}?ref=mail&transactionId=${transactionId}">Review Order</a>
        `;
        mail.sendMail(
          'orders@tarpit.com',
          result.email,
          `Order Successfully Processed`,
          message
        );
      } else {
        console.error('DB connection not available');
      }
    } catch (ex) {
      logger.error(ex);
    }
  }
}

module.exports = new Order();




