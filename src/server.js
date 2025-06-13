const express = require('express');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const session = require('express-session');
const crypto = require('crypto');
const helmet = require('helmet');
const winston = require('winston');

const { logger } = require('./Logger');
const registerApiRoutes = require('./api');
const registerViewRoutes = require('./views');
const { SecretManager } = require('./SecretManager');

// Create secure server
const app = express();
const port = process.env.PORT || 8088;

// Apply security headers
app.use(helmet());

// Initialize secure secret manager
const secretManager = new SecretManager();

// Secure credential retrieval with enhanced validation, audit logging and fallback
const getSessionSecret = async () => {
  try {
    // Attempt to get secret from secure storage service
    const secret = await secretManager.getSecret('SESSION_SECRET_KEY');
    
    // Log credential access for audit (without exposing the secret)
    logger.info('Session secret accessed', { 
      timestamp: new Date().toISOString(),
      action: 'credential_access',
      credential_type: 'session_secret',
      success: true,
      source_ip: process.env.SERVER_IP || 'unknown'
    });
    
    return secret;
  } catch (error) {
    // Log failed credential access attempt
    logger.warn('Failed to retrieve session secret', {
      timestamp: new Date().toISOString(),
      action: 'credential_access_failed',
      credential_type: 'session_secret',
      error_type: error.name,
      source_ip: process.env.SERVER_IP || 'unknown'
    });
    
    // Fallback to environment variable with enhanced validation
    const envSecret = process.env.SESSION_SECRET_KEY;
    if (envSecret) {
      // Validate secret meets enhanced security requirements
      if (!isStrongSecret(envSecret)) {
        logger.error('SESSION_SECRET_KEY does not meet security requirements');
        
        // Fallback to read-only mode instead of exiting
        app.use((req, res, next) => {
          if (req.method !== 'GET') {
            return res.status(503).send('Service in limited mode due to security configuration issue');
          }
          next();
        });
        
        // Generate temporary secret for read-only operations
        return crypto.randomBytes(64).toString('hex');
      }
      return envSecret;
    }
    
    // In production, alert security team
    if (process.env.NODE_ENV === 'production') {
      // Send alert through monitoring system
      alertSecurityTeam('Missing session secret in production environment');
    }
    
    // Use temporary secret (secure but will invalidate all sessions on restart)
    logger.warn('Using temporary session secret - all sessions will be invalidated on restart');
    return crypto.randomBytes(64).toString('hex');
  }
};

// Validate secret strength with enhanced rules
function isStrongSecret(secret) {
  if (secret.length < 32) return false;
  
  // Check for character diversity (upper, lower, numbers, special)
  const hasUpper = /[A-Z]/.test(secret);
  const hasLower = /[a-z]/.test(secret);
  const hasNumber = /[0-9]/.test(secret);
  const hasSpecial = /[^A-Za-z0-9]/.test(secret);
  
  // Calculate entropy score
  const entropy = calculateEntropy(secret);
  
  // Must meet at least 3 character type requirements and have sufficient entropy
  return ((hasUpper + hasLower + hasNumber + hasSpecial) >= 3) && (entropy > 100);
}

// Calculate password entropy
function calculateEntropy(str) {
  const charSetSize = getCharacterSetSize(str);
  return Math.log2(Math.pow(charSetSize, str.length));
}

function getCharacterSetSize(str) {
  const hasUpper = /[A-Z]/.test(str) ? 26 : 0;
  const hasLower = /[a-z]/.test(str) ? 26 : 0;
  const hasNumber = /[0-9]/.test(str) ? 10 : 0;
  const hasSpecial = /[^A-Za-z0-9]/.test(str) ? 33 : 0;
  return hasUpper + hasLower + hasNumber + hasSpecial;
}

// Alert security team through preferred channel
function alertSecurityTeam(message) {
  logger.error(`SECURITY ALERT: ${message}`);
  // Additional alert mechanisms would go here (e.g. email, SMS, monitoring service)
}

// Setup secure error handling middleware
app.use(function(err, req, res, next) {
  const sanitizedError = {
    message: 'An internal server error occurred',
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString()
  };
  
  // Log full error details for internal debugging
  logger.error('Server error', {
    error_id: sanitizedError.id,
    error_message: err.message,
    error_stack: err.stack,
    request_path: req.path,
    request_method: req.method
  });
  
  // Return sanitized error to client
  res.status(500).json(sanitizedError);
});

// Secure body parsing
app.use(bodyParser.urlencoded({ extended: false, limit: '1mb' }));
app.use(bodyParser.json({ limit: '1mb' }));

app.use(cookieParser());

// Initialize environment with secure defaults
const initializeEnvironment = async () => {
  const sessionSecret = await getSessionSecret();
  
  const tarpitEnv = {
    sessionSecretKey: sessionSecret,
    applicationPort: port,
    startTime: new Date().toISOString(),
    // Additional secure configuration settings
    securityLevel: process.env.SECURITY_LEVEL || 'high',
    maxRequestSize: process.env.MAX_REQUEST_SIZE || '1mb'
  };
  
  app.set('tarpitEnv', tarpitEnv);
  
  // Setup secure session
  app.use(
    session({
      secret: tarpitEnv.sessionSecretKey,
      resave: false,
      saveUninitialized: false,
      name: 'sessionId', // Don't use default name to avoid fingerprinting
      cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 3600000 // 1 hour
      },
      // Protect memory from exposing session data
      store: process.env.NODE_ENV === 'production' 
        ? new (require('connect-redis'))(session)({ /* redis config */ }) 
        : new session.MemoryStore()
    })
  );
  
  // Setup secure views
  app.set('view engine', 'pug');
  app.set('views', `./src/Views`);
  
  // Register routes
  registerApiRoutes(app);
  registerViewRoutes(app);
  
  // Audit middleware that safely logs request metadata without exposing sensitive data
  app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
      const duration = Date.now() - start;
      logger.info('Request processed', {
        method: req.method,
        path: req.path,
        status: res.statusCode,
        duration,
        user_id: req.session?.userId || 'anonymous'
      });
    });
    next();
  });
  
  // Start server
  app.listen(port, () => {
    logger.info(
      `Tarpit App listening on port ${port}. Open url: http://localhost:${port}`,
      {
        startup_time: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        port
      }
    );
  });
};

// Start secure application
initializeEnvironment().catch(error => {
  logger.error('Failed to initialize application', {
    error_message: error.message,
    stack: error.stack
  });
  process.exit(1);
});

);
