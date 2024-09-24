const fs = require("fs");
const { logger } = require("../Logger");

class ImageLookup {
get(req, res) {
  // Step 1: Validate the input
  if (!req.query.image) {
    return res.status(400).send('Missing image parameter');
  }

  // Step 2: Sanitize the input
  const sanitizedImage = sanitizeFilename(req.query.image);

  // Step 3: Use the sanitized input to read the file
  let fileContent;
  try {
    fileContent = fs.readFileSync(sanitizedImage).toString();
  } catch (error) {
    return res.status(404).send('File not found');
  }

  logger.debug(fileContent);
  res.send(fileContent);
}

}

module.exports = ImageLookup;

