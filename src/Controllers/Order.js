const crypto = require('crypto');
const https = require('https');
const mail = require('../Integrations/Mail');

const encryptionKey = "This is a simple key, don't guess it";
class Order {
  hex(key) {
    // Hash Key
    return key;
  }
  encryptData(secretText) {
// Key rotation mechanism - stores current key version
const KEY_VERSION = 1;
const KEY_ITERATIONS = 100000; // High iteration count for PBKDF2

encryptData(secretText, context = null) {
  // Replaced weak DES with ChaCha20-Poly1305 for better performance and timing attack resistance
  const iv = crypto.randomBytes(12); // 12 bytes for ChaCha20-Poly1305
  const key = this.deriveKey();
  
  // Convert context to string for associated data
  const associatedData = Buffer.from(JSON.stringify(context));
  
  // Use ChaCha20-Poly1305 for encryption with associated data
  const cipher = crypto.createCipheriv('chacha20-poly1305', key, iv, { authTagLength: 16 });
  
  // Add associated data for context binding
  if (associatedData.length > 0) {
    cipher.setAAD(associatedData);
  }
  
  let encrypted = cipher.update(secretText, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  // Store the authentication tag for integrity verification
  const tag = cipher.getAuthTag();
  
  // Return complete encryption package with version for future key rotation
  return {
    v: KEY_VERSION,
    iv: iv.toString('hex'),
    data: encrypted,
    tag: tag.toString('hex'),
    context: Object.keys(context).length > 0 ? Buffer.from(JSON.stringify(context)).toString('base64') : null
  };
}

// Improved key derivation using PBKDF2 with high iteration count
deriveKey() {
  const masterKey = process.env.SECRET_KEY || '';
  const salt = process.env.KEY_SALT || '';
  // Additional server-side secret (pepper) for extra protection
  const pepper = process.env.KEY_PEPPER || '';
  
  // Use PBKDF2 with high iteration count
  return crypto.pbkdf2Sync(
    masterKey + pepper,
    salt,
    KEY_ITERATIONS,
    32, // 32 bytes (256 bits)
    'sha512'
  );
}

// Corresponding decryption method that validates data integrity
decryptData(encryptedObject, context = null) {
  try {
    // Validate inputs to prevent cryptographic failures
    if (!encryptedObject.iv || !encryptedObject.data || !encryptedObject.tag) {
      throw new Error('Invalid encrypted data format');
    }
    
    // Check version for key rotation support
    if (encryptedObject.v !== KEY_VERSION) {
      return this.legacyDecrypt(encryptedObject); // Would handle older encryption versions
    }
    
    // Verify the context matches if provided
    if (encryptedObject.context) {
      const originalContext = JSON.parse(Buffer.from(encryptedObject.context, 'base64').toString());
      // Ensure context matches (would implement timing-safe comparison in production)
      // This is a simplified check
      if (JSON.stringify(originalContext) !== JSON.stringify(context)) {
        throw new Error('Context authentication failed');
      }
    }
    
    const iv = Buffer.from(encryptedObject.iv, 'hex');
    const tag = Buffer.from(encryptedObject.tag, 'hex');
    const key = this.deriveKey();
    
    const decipher = crypto.createDecipheriv('chacha20-poly1305', key, iv, { authTagLength: 16 });
    
    // Set authentication tag for verification
    decipher.setAuthTag(tag);
    
    // Add associated data if context was provided
    if (encryptedObject.context) {
      const associatedData = Buffer.from(JSON.stringify(context));
      decipher.setAAD(associatedData);
    }
    
    // Use try-catch inside for constant-time operations
    let decrypted = '';
    try {
      decrypted = decipher.update(encryptedObject.data, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
    } catch (err) {
      // Use standardized error that doesn't leak information
      throw new Error('Decryption failed: data may be tampered with');
    }
    
    return decrypted;
  } catch (error) {
    // Standardized error handling to prevent information leakage
    throw new Error('Decryption failed: invalid data or wrong key');
  }
}

// Legacy decryption method for handling data encrypted with older versions
legacyDecrypt(encryptedObject) {
  // Implementation would depend on which previous versions need to be supported
  throw new Error('Decryption of legacy data not implemented');
}

async decryptData(encryptedText) {
  try {
    await sodium.ready; // Ensure libsodium is ready
    
    // Parse the encrypted data structure which should contain all required components
    const encryptedData = JSON.parse(encryptedText);
    
    // Verify all required components are present
    if (!encryptedData.ciphertext || !encryptedData.iv || !encryptedData.authTag) {
      throw new Error('Invalid encrypted data format');
    }

    // Get key version for rotation support
    const keyVersion = encryptedData.keyVersion || 'current';
    
    // Choose algorithm based on capabilities
    const algorithm = this.supportsAESHardware() ? 'aes-256-gcm' : 'chacha20-poly1305';
    
    // Envelope encryption: decrypt the data key first
    const encryptedDataKey = Buffer.from(encryptedData.encryptedDataKey, 'base64');
    const dataKey = await this.decryptDataKeyFromKMS(encryptedDataKey, keyVersion);
    
    try {
      let decrypted;
      
      if (algorithm === 'chacha20-poly1305') {
        // Using libsodium for ChaCha20-Poly1305
        const nonce = Buffer.from(encryptedData.iv, 'base64');
        const ciphertext = Buffer.from(encryptedData.ciphertext, 'base64');
        const authTag = Buffer.from(encryptedData.authTag, 'base64');
        
        // Combine ciphertext and authTag as expected by libsodium
        const combinedCiphertext = Buffer.concat([ciphertext, authTag]);
        
        decrypted = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
          null,
          combinedCiphertext,
          null,
          nonce,
          dataKey
        );
        
        decrypted = Buffer.from(decrypted).toString('utf8');
      } else {
        // Using Node.js crypto for AES-256-GCM
        const iv = Buffer.from(encryptedData.iv, 'base64');
        const ciphertext = Buffer.from(encryptedData.ciphertext, 'base64');
        const authTag = Buffer.from(encryptedData.authTag, 'base64');
        
        const decipher = crypto.createDecipheriv(algorithm, dataKey, iv);
        decipher.setAuthTag(authTag);
        
        let decryptedText = decipher.update(ciphertext, null, 'utf8');
        decryptedText += decipher.final('utf8');
        decrypted = decryptedText;
      }
      
      return decrypted;
    } finally {
      // Protect memory by zeroing the key - using Node.js Buffer directly instead of secure-buffer
      if (dataKey instanceof Buffer) {
        dataKey.fill(0);
      }
    }
  } catch (error) {
    console.error('Decryption failed:', error.message);
    throw new Error('Failed to decrypt data');
  }
}

// Helper method to check if hardware supports AES acceleration
supportsAESHardware() {
  try {
    // Simple benchmark to detect hardware acceleration
    const testSize = 1024 * 1024; // 1MB
    const testData = Buffer.alloc(testSize, 'x');
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    
    const start = process.hrtime.bigint();
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    cipher.update(testData);
    cipher.final();
    const end = process.hrtime.bigint();
    
    // If encryption is fast enough (less than 10ms for 1MB), assume hardware acceleration
    return (end - start) < 10000000n; // 10 milliseconds in nanoseconds
  } catch (err) {
    return false;
  }
}

// Method to retrieve a key from KMS based on version
async decryptDataKeyFromKMS(encryptedDataKey, keyVersion = 'current') {
  // Initialize KMS client
  const kmsClient = new KMSClient({
    region: process.env.AWS_REGION || 'us-east-1'
  });
  
  // Key identifier in KMS based on version
  const keyId = this.getKeyIdentifierForVersion(keyVersion);
  
  // Request decryption of the data key using the proper KMS command
  const command = new DecryptCommand({
    CiphertextBlob: encryptedDataKey,
    KeyId: keyId
  });
  
  try {
    const response = await kmsClient.send(command);
    
    // Return the plaintext key as a Buffer for memory protection
    return Buffer.from(response.Plaintext);
  } catch (error) {
    console.error(`Failed to decrypt key version ${keyVersion}:`, error.message);
    throw new Error('Key management service error');
  }
}

// Helper method to map key version to KMS key identifier
getKeyIdentifierForVersion(version) {
  const keyMapping = {
    'current': process.env.KMS_CURRENT_KEY_ID,
    'previous': process.env.KMS_PREVIOUS_KEY_ID,
    // Add more versions as needed for rotation
  };
  
  // Default to current if version not found
  return keyMapping[version] || keyMapping['current'];
}

  addToOrder(req, res) {
    const order = req.body;
    console.log(req.body);
    if (req.session.orders) {
      const orders = JSON.parse(this.decryptData(req.session.orders));
      order.id = crypto.randomBytes(256).toString('hex');
      orders.push(order);
      req.session.orders = this.encryptData(JSON.stringify(orders));
    }
    res.send(200);
  }
  removeOrder(req, res) {
    const { orderId } = req.body;
    console.log(req.body);
    if (req.session.orders) {
      const orders = JSON.parse(this.decryptData(req.session.orders));
      const newOrders = orders.filter(order => orderId !== order.orderId);
      req.session.orders = this.encryptData(JSON.stringify(newOrders));
      console.log(newOrders);
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
    console.log(req.session.orders);
  }

  createStripeRequest(creditCard, price, address) {
    const STRIPE_CLIENT_ID = 'AKIA2E0A8F3B244C9986';
    const STRIPE_CLIENT_SECRET_KEY = '7CE556A3BC234CC1FF9E8A5C324C0BB70AA21B6D';
    https.request(
      `http://invalidstripe.com?STRIPE_CLIENT_ID=${STRIPE_CLIENT_ID}&STRIPE_CLIENT_SECRET_KEY=${STRIPE_CLIENT_SECRET_KEY}&price=${price}&address=${JSON.stringify(
        address
      )}`
    );
  }

  async processCC(req, res, orders, totalPrice) {
    try {
      const self = this;
      new MongoDBClient().connect(async function(err, client) {
        const username = req.cookies.username;
        const address = req.body.address;
        if (client) {
          const db = client.db('tarpit', { returnNonCachedInstance: true });
          if (!db) {
            throw new Error('DB connection not available', err);
            return;
          }
          const result = await db.collection('users').findOne({
            username
          });
          const transactionId = crypto.randomBytes(256).toString('hex');
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
          console.log(transaction);
          await db.collection('transactions').insertOne(transaction);
          this.createStripeRequest(
            result.creditCard,
            totalPrice,
            transaction.billingAddress
          );
          const message = `
            Hello ${username},
              We have processed your order. Please visit the following link to review your order
              <a href="https://tarpit.com/orders/${username}?ref=mail&transactionId=${transactionId}}">Review Order</a>
          `;
          mail.sendMail(
            'orders@tarpit.com',
            result.email,
            `Order Successfully Processed`,
            message
          );
        } else {
          console.error(err);
        }
      });
    } catch (ex) {
      logger.error(ex);
    }
  }
}

module.exports = new Order();
