const { validationResult, body } = require('express-validator');

const validate = validations => {
    return async (req, res, next) => {
      for (let validation of validations) {
        const result = await validation.run(req);
        if (result.errors.length) break;
      }
  
      const errors = validationResult(req);
      if (errors.isEmpty()) {
        return next();
      }
  
      res.status(400).send({message: "Invalid data"});
    };
};

const credentialsValidations = [
  body('email').isEmail(),
  body('password').isLength({max: 16}),
  body('password').isStrongPassword({
      minLength: 8,
      minLowercase: 1,
      minUppercase: 1,
      minNumbers: 1,
      minSymbols: 1
  })
]

module.exports = {
  validate,
  credentialsValidations
};