import createError from 'http-errors';
import express from 'express';
import path from 'path';
import cors from 'cors';
import passport from 'passport';
import session from 'express-session';
import flash from 'express-flash';
import cookieParser from 'cookie-parser';
import methodOverride from 'method-override';
import config from './config';

const expressLayouts = require('express-ejs-layouts');
const app = express();

// view engine setup
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());
app.set('views', path.join(__dirname, 'src', 'views'));
app.set('view engine', 'ejs');
app.use('/public', express.static(path.join(__dirname, '.', 'public')));
app.use(
  '/images',
  express.static(path.join(__dirname, '.', 'public', 'uploads', 'images'))
);
app.use(expressLayouts);
require('./src/util/passport')(passport);
app.use(flash());
app.use(
  session({
    cookie: { maxAge: 86400000 },
    secret: config.SESSION_SECRET,
    resave: true,
    saveUninitialized: false
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride('_method'));
app.use(cors());

const UserRouter = require('./src/routes/user.route')(app, passport);
app.use('/api/user', UserRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

app.listen(process.env.PORT, () => {
  console.log(`Server listen on port ${process.env.PORT}`);
});
// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
