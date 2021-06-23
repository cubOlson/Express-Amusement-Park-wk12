const express = require('express')
const bcrypt = require('bcrypt')
const { check, validationResult } = require('express-validator');
const db = require('../db/models');
const { csrfProtection, asyncHandler } = require('./utils');

const router = express.Router()

const userValidators = [
    check('firstName')
    .exists({ checkFalsy: true })
    .withMessage('Please provide a value for First Name')
    .isLength({ max: 50 })
    .withMessage('First Name must not be more than 50 characters long'),
  check('lastName')
    .exists({ checkFalsy: true })
    .withMessage('Please provide a value for Last Name')
    .isLength({ max: 50 })
    .withMessage('Last Name must not be more than 50 characters long'),
  check('emailAddress')
    .exists({ checkFalsy: true })
    .withMessage('Please provide a value for Email Address')
    .isEmail()
    .withMessage('Please provide a valid email address')
    .custom((value) => {
        return db.User.findOne({ where: { emailAddress: value}})
            .then((user) => {
                if (user) {
                    return Promise.reject('The provided email address is already in use')
                }
            })
    }),
  check('password')
    .exists({ checkFalsey: true })
    .withMessage('Please provide a value for Password')
    .isLength({ max: 50 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])/, 'g')
    .withMessage('Password must contain at least 1 lowercase letter, uppercase letter, number, and special character (i.e. "!@#$%^&*")'),
  check('confirmPassword')
    .exists({ checkFalsey: true })
    .isLength({ max: 50 })
    .custom((value, { req }) => {
        if (value !== req.body.password) {
            throw new Error('Confirm Password does not match Password')
        }
        return true;
    }),
];

router.get('/user/register', csrfProtection, asyncHandler(async(req, res) => {
    const user = db.User.build();
    res.render('user-register', {
        title: 'Register',
        user,
        csrfToken: req.csrfToken(),
    });
}));

router.post('/user/register', userValidators, csrfProtection, asyncHandler(async(req, res) => {
    const { emailAddress, firstName, lastName, password } = req.body;

    const user = db.User.build({
        emailAddress,
        firstName,
        lastName,
    });

    const validatorErrors = validationResult(req);

    if (validatorErrors.isEmpty()) {
        const hashedPassword = await bcrypt.hash(password, 10);
        user.hashedPassword = hashedPassword;
        await user.save();
        res.redirect('/');
    } else {
        const errors = validatorErrors.array().map((error) => error.msg);
        res.render('user-register', {
            title: 'Register',
            user,
            errors,
            csrfToken: req.csrfToken()
        })
    }
}));

const loginValidators = [
    check('emailAddress')
]

router.get('/user/login', csrfProtection, asyncHandler((req, res) => {
    res.render('user-login', {
        title: 'Login',
        csrfToken: req.csrfToken(),
    });
}));

router.post('/user/login', csrfProtection, asyncHandler((req, res) => {

}))

module.exports = router;
