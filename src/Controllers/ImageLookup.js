const fs = require("fs");
const { logger } = require("../Logger");

class ImageLookup {
get(req, res) {
  try {
    const sanitizedFilename = sanitizeFilename(req.query.image);
    const filePath = path.join(__dirname, '..', 'uploads', sanitizedFilename);
    const fileContent = fs.readFileSync(filePath, 'utf8');
    logger.info(fileContent);
    res.send(fileContent);
  } catch (error) {
    logger.error(error);
    res.status(500).send('An error occurred while reading the file.');
  }
}

}

module.exports = ImageLookup;

