const multer = require('multer');
const path = require('path');
const fs = require('fs');
const sharp = require('sharp');

// Ensure upload directory exists
const uploadDir = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const optimizedDir = path.join(__dirname, '..', 'uploads', 'optimized');
if (!fs.existsSync(optimizedDir)) {
  fs.mkdirSync(optimizedDir, { recursive: true });
}

// Storage configuration for Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1e9)}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

// File filter - only allow images
const fileFilter = (req, file, cb) => {
  const allowedMimes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
  if (allowedMimes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Only image files are allowed'), false);
  }
};

// Multer upload configuration
const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  }
});

/**
 * Optimize image using Sharp
 * Resizes, converts to WebP, and compresses
 */
const optimizeImage = async (filePath, maxWidth = 1200, maxHeight = 1200) => {
  try {
    const filename = path.basename(filePath);
    const optimizedPath = path.join(optimizedDir, `optimized-${filename}.webp`);

    await sharp(filePath)
      .resize(maxWidth, maxHeight, {
        fit: 'inside',
        withoutEnlargement: true
      })
      .webp({ quality: 80 })
      .toFile(optimizedPath);

    return {
      success: true,
      originalPath: filePath,
      optimizedPath,
      optimizedUrl: `/uploads/optimized/optimized-${filename}.webp`
    };
  } catch (error) {
    return {
      success: false,
      error: error.message
    };
  }
};

/**
 * Middleware: Upload single image
 */
const uploadSingleImage = upload.single('image');

/**
 * Middleware: Upload single image with optimization
 */
const uploadAndOptimizeImage = async (req, res, next) => {
  uploadSingleImage(req, res, async (err) => {
    if (err) {
      return res.status(400).json({
        error: 'File upload failed',
        message: err.message
      });
    }

    if (!req.file) {
      return next();
    }

    try {
      const result = await optimizeImage(req.file.path);
      if (result.success) {
        req.file.optimizedUrl = result.optimizedUrl;
      }
      next();
    } catch (error) {
      return res.status(500).json({
        error: 'Image optimization failed',
        message: error.message
      });
    }
  });
};

/**
 * Middleware: Upload multiple images (up to 5)
 */
const uploadMultipleImages = upload.array('images', 5);

/**
 * Middleware: Upload multiple images with optimization
 */
const uploadAndOptimizeMultipleImages = async (req, res, next) => {
  uploadMultipleImages(req, res, async (err) => {
    if (err) {
      return res.status(400).json({
        error: 'File upload failed',
        message: err.message
      });
    }

    if (!req.files || req.files.length === 0) {
      return next();
    }

    try {
      const optimizedFiles = [];
      for (const file of req.files) {
        const result = await optimizeImage(file.path);
        if (result.success) {
          optimizedFiles.push({
            originalFile: file,
            optimizedUrl: result.optimizedUrl
          });
        }
      }
      req.optimizedFiles = optimizedFiles;
      next();
    } catch (error) {
      return res.status(500).json({
        error: 'Image optimization failed',
        message: error.message
      });
    }
  });
};

/**
 * Validate image URL format
 */
const validateImageUrl = (url) => {
  if (!url) return { valid: false, error: 'URL is required' };
  
  try {
    new URL(url);
    const imageExtensions = ['.jpg', '.jpeg', '.png', '.webp', '.gif'];
    const lowerUrl = url.toLowerCase();
    const hasValidExtension = imageExtensions.some(ext => lowerUrl.includes(ext));
    
    if (!hasValidExtension) {
      return { valid: false, error: 'URL must point to an image file' };
    }
    
    return { valid: true };
  } catch (error) {
    return { valid: false, error: 'Invalid URL format' };
  }
};

module.exports = {
  uploadSingleImage,
  uploadAndOptimizeImage,
  uploadMultipleImages,
  uploadAndOptimizeMultipleImages,
  optimizeImage,
  validateImageUrl
};
