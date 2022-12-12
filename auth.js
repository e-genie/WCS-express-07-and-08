const argon2 = require("argon2");

const hashingOptions = {
  type: argon2.argon2id,
  memoryCost: 2 ** 16,
  timeCost: 5,
  parallelism: 1,
};

const hashPassword = async (req, res, next) => {
  try {
    console.log(req.body);
    const hashedPassword = await argon2.hash(req.body.password, hashingOptions);

    console.log(hashedPassword);
    req.body.hashedPassword = hashedPassword;
    delete req.body.password;
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
  next();
};

module.exports = {
  hashPassword,
};
