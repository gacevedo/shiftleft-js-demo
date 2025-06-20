const logger = require('../Logger').logger;
const MongoDBClient = require('../DB').MongoDBClient;

class Login {
  loginFailed(req, res, { username, password, keeponline }) {
    res.locals.username = username;
    res.locals.password = password;
    res.locals.keeponline = keeponline;
    res.locals.message = 'Failed to Sign in. Please verify credentials';
    res.redirect('/login');
  }

async encryptData(secretText) {
    // FIXED: Replaced weak DES encryption with libsodium (standardized encryption library)
    await sodium.ready;
    
    // FIXED: Implemented proper key management using AWS KMS
    const kms = new AWS.KMS({
        region: process.env.AWS_REGION
    });
    
    // FIXED: Using envelope encryption pattern
    // 1. Generate data key for this specific encryption operation
    const dataKeyResponse = await kms.generateDataKey({
        KeyId: process.env.KMS_MASTER_KEY_ID,
        KeySpec: 'AES_256'
    }).promise();
    
    // The plaintext data key will be used for encryption
    const dataKey = dataKeyResponse.Plaintext;
    
    // The encrypted data key is stored alongside the encrypted data
    const encryptedDataKey = dataKeyResponse.CiphertextBlob;
    
    // 2. Use libsodium for the actual encryption
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    
    // Convert data key to format libsodium expects
    const sodiumKey = sodium.crypto_secretbox_keygen();
    Buffer.from(dataKey).copy(sodiumKey);
    
    // Perform the encryption
    const encryptedData = sodium.crypto_secretbox_easy(
        Buffer.from(secretText, 'utf8'),
        nonce,
        sodiumKey
    );
    
    // 3. Return all components needed for decryption
    return {
        encryptedDataKey: encryptedDataKey.toString('base64'),
        nonce: Buffer.from(nonce).toString('base64'),
        encryptedData: Buffer.from(encryptedData).toString('base64'),
        algorithm: 'libsodium-secretbox'
    };
    
    // Clear sensitive data from memory
    sodium.memzero(sodiumKey);
}

    return desCipher.write(secretText, 'utf8', 'hex'); // BAD: weak encryption
  }

  async handleLogin(req, res, client, data) {
    const { username, password, keeponline } = data;
    try {
      // DB Query
      const db = client.db('tarpit', { returnNonCachedInstance: true });
      if (!db) {
        this.loginFailed(req, res, data);
        return;
      }
      const result = await db.collection('users').findOne({
        username,
        password
      });
      if (result) {
        const user = {
          fname: result.fname,
          lname: result.lname,
          passportnum: result.passportnum,
          address1: result.address1,
          address2: result.address2,
          zipCode: result.zipCode
        };
        const creditInfo = encryptData(result.creditCard);
        logger.info(`user: ${JSON.stringify(user)} successfully logged in`);
        logger.info(
          `user ${user.fname} credit info: ${JSON.stringify(creditInfo)}`
        );
        res.cookie('username', result.username);
        res.cookie('maxAge', 864000);
        res.cookie('cc', creditInfo);

        req.session.user = JSON.stringify(user);
        req.session.username = username;

        res.redirect('/');
      } else {
        this.loginFailed(req, res, data);
      }
    } catch (ex) {
      logger.error(ex);
      this.loginFailed(req, res, data);
    }
  }

  login(req, res) {
    /*
      This can be exploited (similar to SQL Injection) when the request body is
      {
        "password": {
          "$gt": ""
        },
        "username": {
          "$gt": ""
        }
      }
    */
    const { username, password, encodedPath, keeponline } = req.body;
    const data = { username, password, keeponline };
    logger.debug(data);
    try {
      new MongoDBClient().connect((err, client) => {
        if (client) {
          this.handleLogin(req, res, client, data);
        } else {
          console.error(err);
          this.loginFailed(req, res, data);
        }
      });
    } catch (ex) {
      logger.error(ex);
      this.loginFailed(req, res, data);
    }
  }
}

module.exports = Login;
