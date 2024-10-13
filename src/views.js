const secured = require('./Controllers/Secured');

module.exports = app => {
  // Exploits app Env
  app.get('/env', (req, res) => {
    console.log(app.get(req.query.lookup));
    res.send(app.get(req.query.lookup));
  });
  app.get(`/login`, (req, res) => res.render('Login'));

(req, res) => {
  let result = '';
  try {
    const userInput = xssFilters.inHTMLData(req.query.userInput); // Sanitize user input
    result = util.inspect(db.query(userInput)); // Use parameterized query or stored procedure
  } catch (ex) {
    console.error(ex);
    result = 'An error occurred while processing your request.';
  }
  res.render('UserInput', {
    userInput: userInput, // Explicitly passing sanitized input to template
    result: result,
    date: new Date().toUTCString()
  });
}

  });

  app.get(`/`, secured.get);
  app.post(`/`, secured.post);
};

