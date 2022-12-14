const argon2 = require("argon2");
const jwt = require("jsonwebtoken");

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

const verifyPassword = (req, res) => {
  argon2

    .verify(req.user.hashedPassword, req.body.password)

    .then((isVerified) => {
      if (isVerified) {
        const payload = { sub: req.user.id };

        const token = jwt.sign(payload, process.env.JWT_SECRET, {
          expiresIn: "1h",
        });

        delete req.user.hashedPassword;

        res.send({ token, user: req.user });
      } else {
        res.sendStatus(401);
      }
    })

    .catch((err) => {
      console.error(err);

      res.sendStatus(500);
    });
};

const verifyToken = (req, res, next) => {
  try {
    const authorizationHeader = req.get("Authorization");

    if (authorizationHeader == null) {
      throw new Error("Authorization header is missing");
    }

    const [type, token] = authorizationHeader.split(" ");

    if (type !== "Bearer") {
      throw new Error("Authorization header has not the 'Bearer' type");
    }

    req.payload = jwt.verify(token, process.env.JWT_SECRET);

    next();
  } catch (err) {
    console.error(err);

    res.sendStatus(401);
  }
};

const verifyId = (req, res, next) => {
  try {
    const authorizedId = +req.params.id;
    if (authorizedId !== req.payload.sub) {
      throw new Error("Forbidden");
    }
    next();
  } catch (err) {
    console.error(err);

    res.sendStatus(403);
  }
};

module.exports = {
  hashPassword,
  verifyPassword,
  verifyToken,
  verifyId,
};
