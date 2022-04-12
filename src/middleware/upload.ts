import multer from "multer";
import path from "path";
import { exists, mkdir } from "fs";

const maxSize = 5 * 1024 * 1024;
let storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, "../../public/uploads/images");
    exists(dir, exist => {
      if (!exist) {
        return mkdir(dir, { recursive: true }, error => cb(error, dir));
      }
      cb(null, dir);
    });
  },
  filename: (req, file, cb) => {
    cb(null, file.fieldname + "_" + Date.now() + path.extname(file.originalname));
  },
});
let uploadFile = multer({
  storage: storage,
  limits: { fileSize: maxSize },
  fileFilter(req, file, cb) {
    if (!file.originalname.match(/\.(png|jpg|jpeg|svg)$/)) {
      return cb("Invalid format");
    }
    cb(undefined, true);
  },
});
module.exports = uploadFile;
