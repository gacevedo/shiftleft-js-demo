const secured = require('./Controllers/Secured');

module.exports = app => {
  // Exploits app Env
  app.get('/env', (req, res) => {
    console.log(app.get(req.query.lookup));
    res.send(app.get(req.query.lookup));
  });
  app.get(`/login`, (req, res) => res.render('Login'));

(req, res) => {
  /* QWIETAI-AUTOFIX: Start */
  let userInput = DOMPurify.sanitize(req.query.userInput); // sanitize user input
  let result = '';
  try {
    result = util.inspect(eval(userInput)); // use eval safely
  } catch (ex) {
    console.error(ex);
  }
  res.render('UserInput', {
    userInput: userInput, // sanitized input
    result: DOMPurify.sanitize(result), // sanitize output
    date: new Date().toUTCString()
  });
  /* QWIETAI-AUTOFIX: End */
}

  });

  app.get(`/`, secured.get);
  app.post(`/`, secured.post);
};

