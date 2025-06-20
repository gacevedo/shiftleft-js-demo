const fs = require("fs");
const { logger } = require("../Logger");

class ImageLookup {
  get(req, res) {
// Create a rate limiter middleware
const imageLookupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many image requests from this IP, please try again later'
});

get(req, res) {
  // Apply rate limiting
  imageLookupLimiter(req, res, () => {
    try {
      // Define a whitelist of allowed image directories
      const ALLOWED_DIR = path.resolve(__dirname, '../public/images');
      
      // Sanitize and validate the filename
      const filename = req.query.image;
      if (!filename || typeof filename !== 'string') {
        return res.status(400).send('Invalid image parameter');
      }
      
      // Use sanitize-filename library for more robust input validation
      const sanitizedFilename = sanitizeFilename(filename);
      
      // Add file extension whitelist
      const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.svg'];
      const fileExt = path.extname(sanitizedFilename).toLowerCase();
      if (!allowedExtensions.includes(fileExt)) {
        logger.warn(`Disallowed file extension attempt: ${fileExt} from ${req.ip}`);
        return res.status(403).send('File type not allowed');
      }
      
      // Create the absolute path and validate it's within allowed directory
      const filepath = path.resolve(ALLOWED_DIR, path.basename(sanitizedFilename));
      
      // Security check to prevent directory traversal
      if (!filepath.startsWith(ALLOWED_DIR)) {
        logger.warn(`Directory traversal attempt: ${sanitizedFilename} from ${req.ip}`);
        return res.status(403).send('Access denied');
      }
      
      // Use async file operations instead of synchronous ones
      fs.promises.stat(filepath)
        .then(stats => {
          if (!stats.isFile()) {
            return Promise.reject(new Error('Not a file'));
          }
          
          // Set appropriate content type headers based on file extension
          const mimeTypes = {
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.svg': 'image/svg+xml'
          };
          res.setHeader('Content-Type', mimeTypes[fileExt] || 'application/octet-stream');
          
          // Add security headers
          res.setHeader('Content-Security-Policy', "default-src 'self'");
          res.setHeader('X-Content-Type-Options', 'nosniff');
          
          // Stream the file instead of loading it into memory
          logger.debug(`Serving file: ${filepath}`);
          return fs.createReadStream(filepath).pipe(res);
        })
        .catch(error => {
          logger.error(`Error accessing image: ${error.message}`);
          res.status(404).send('File not found');
        });
    } catch (error) {
      logger.error(`Error processing request: ${error.message}`);
      res.status(500).send('Internal server error');
    }
  });
}


module.exports = ImageLookup;
