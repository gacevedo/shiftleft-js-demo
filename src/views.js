const secured = require('./Controllers/Secured');

module.exports = app => {
  // Exploits app Env
  app.get('/env', (req, res) => {
    console.log(app.get(req.query.lookup));
    res.send(app.get(req.query.lookup));
  });
  app.get(`/login`, (req, res) => res.render('Login'));

  app.get(`/user-input`, (req, res) => {
(req, res) => {
    /*
      User input handling with secure evaluation
      Using mathjs library with enhanced security measures
    */
    let result = '';
    try {
      // Get user input with explicit sanitization
      const userInput = req.query.userInput || '';
      
      // Added explicit input length check to prevent DoS attacks
      if (userInput.length > 100) {
        result = 'Input too long: maximum 100 characters allowed';
      } 
      // Enhanced regex validation - more restrictive, only basic math operations
      else if (/^[0-9+\-*/().\s]+$/.test(userInput)) {
        // Use mathjs evaluate with security options
        const mathOptions = {
          // Limit available functions and expressions for security
          // Only allow basic arithmetic operations
          mathjs: {
            number: 'number',
            string: false,
            meta: false,
            Matrix: false,
            Array: false,
            Object: false,
            classes: false
          }
        };
        
        // Safely evaluate with mathjs
        result = math.evaluate(userInput, mathOptions).toString();
      } else {
        result = 'Invalid input: only basic mathematical expressions allowed';
      }
    } catch (ex) {
      console.error('Error evaluating expression:', ex.message);
      result = 'Error evaluating expression';
    }
    
    // Create DOMPurify instance for sanitizing output
    const window = new JSDOM('').window;
    const DOMPurify = createDOMPurify(window);
    
    // Add Content Security Policy headers
    res.set('Content-Security-Policy', "default-src 'self'");
    
    res.render('UserInput', {
      // Apply output encoding via DOMPurify to prevent XSS
      userInput: DOMPurify.sanitize(req.query.userInput || ''),
      result: DOMPurify.sanitize(result),
      date: new Date().toUTCString()
    });
  }

  app.get(`/`, secured.get);
  app.post(`/`, secured.post);
};
