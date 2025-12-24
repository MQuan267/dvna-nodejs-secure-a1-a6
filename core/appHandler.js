var db = require("../models");
var bCrypt = require("bcrypt");
const execFile = require("child_process").execFile;
var mathjs = require("mathjs");
var libxmljs = require("libxmljs");
var serialize = require("node-serialize");
const Op = db.Sequelize.Op;

module.exports.userSearch = function (req, res) {
  db.User.find({ where: { login: req.body.login } })
    .then((user) => {
      if (user) {
        var output = {
          user: {
            name: user.name,
            id: user.id,
          },
        };
        res.render("app/usersearch", {
          output: output,
        });
      } else {
        req.flash("warning", "User not found");
        res.render("app/usersearch", {
          output: null,
        });
      }
    })
    .catch((err) => {
      req.flash("danger", "Internal Error");
      res.render("app/usersearch", {
        output: null,
      });
    });
};

module.exports.ping = function (req, res) {
  execFile(
    "ping",
    ["-c", "2", req.body.address],
    function (err, stdout, stderr) {
      output = stdout + stderr;
      res.render("app/ping", {
        output: output,
      });
    }
  );
};

module.exports.listProducts = function (req, res) {
  db.Product.findAll().then((products) => {
    output = {
      products: products,
    };
    res.render("app/products", {
      output: output,
    });
  });
};

module.exports.productSearch = function (req, res) {
  db.Product.findAll({
    where: {
      name: {
        [Op.like]: "%" + req.body.name + "%",
      },
    },
  }).then((products) => {
    output = {
      products: products,
      searchTerm: req.body.name,
    };
    res.render("app/products", {
      output: output,
    });
  });
};

module.exports.modifyProduct = function (req, res) {
  if (!req.query.id || req.query.id == "") {
    output = {
      product: {},
    };
    res.render("app/modifyproduct", {
      output: output,
    });
  } else {
    db.Product.find({
      where: {
        id: req.query.id,
      },
    }).then((product) => {
      if (!product) {
        product = {};
      }
      output = {
        product: product,
      };
      res.render("app/modifyproduct", {
        output: output,
      });
    });
  }
};

module.exports.modifyProductSubmit = function (req, res) {
  if (!req.body.id || req.body.id == "") {
    req.body.id = 0;
  }
  db.Product.find({
    where: {
      id: req.body.id,
    },
  }).then((product) => {
    if (!product) {
      product = new db.Product();
    }
    product.code = req.body.code;
    product.name = req.body.name;
    product.description = req.body.description;
    product.tags = req.body.tags;
    product
      .save()
      .then((p) => {
        if (p) {
          req.flash("success", "Product added/modified!");
          res.redirect("/app/products");
        }
      })
      .catch((err) => {
        output = {
          product: product,
        };
        req.flash("danger", err);
        res.render("app/modifyproduct", {
          output: output,
        });
      });
  });
};

module.exports.userEdit = function (req, res) {
  res.render("app/useredit", {
    userId: req.user.id,
    userEmail: req.user.email,
    userName: req.user.name,
  });
};

module.exports.userEditSubmit = function (req, res) {
    const targetUserId = parseInt(req.body.id, 10);

    if (!Number.isInteger(targetUserId)) {
        return res.status(400).send('Invalid user id');
    }

    if (req.user.role !== 'admin' && req.user.id !== targetUserId) {
        return res.status(403).send('Forbidden');
    }

    db.User.findOne({ where: { id: targetUserId } })
        .then(user => {
    if (req.body.password.length > 0) {
      if (req.body.password.length > 0) {
        if (req.body.password == req.body.cpassword) {
          user.password = bCrypt.hashSync(
            req.body.password,
            bCrypt.genSaltSync(10),
            null
          );
        } else {
          req.flash("warning", "Passwords dont match");
          res.render("app/useredit", {
            userId: req.user.id,
            userEmail: req.user.email,
            userName: req.user.name,
          });
          return;
        }
      } else {
        req.flash("warning", "Invalid Password");
        res.render("app/useredit", {
          userId: req.user.id,
          userEmail: req.user.email,
          userName: req.user.name,
        });
        return;
      }
    }
    user.email = req.body.email;
    user.name = req.body.name;
    user.save().then(function () {
      req.flash("success", "Updated successfully");
      res.render("app/useredit", {
        userId: req.body.id,
        userEmail: req.body.email,
        userName: req.body.name,
      });
    });
  });
};

module.exports.redirect = function (req, res) {
  if (req.query.url) {
    res.redirect(req.query.url);
  } else {
    res.send("invalid redirect url");
  }
};

module.exports.calc = function (req, res) {
    const eqn = req.body.eqn;

    //Kiểm tra có dữ liệu hay không
    if (!eqn) {
        return res.render('app/calc', {
            output: 'Enter a valid math string like (3+3)*2'
        });
    }
    //Validate
    const regex = /^[0-9+\-*/().\s]+$/;
    if (!regex.test(eqn)) {
        return res.render('app/calc', {
            output: 'Invalid math expression'
        });
    }

    try {
        const result = mathjs.eval(eqn);
        res.render('app/calc', { output: result });
    } catch (err) {
        res.render('app/calc', {
            output: 'Invalid math expression'
        });
    }
};
module.exports.listUsersAPI = function (req, res) {
  db.User.findAll({ attributes: ["id", "name", "email"] }).then((users) => {
    res.status(200).json({
      success: true,
      users: users,
    });
  });
};

module.exports.bulkProductsLegacy = function (req, res) {
  // TODO: Deprecate this soon
  if (req.files.products) {
    var products = serialize.unserialize(
      req.files.products.data.toString("utf8")
    );
    products.forEach(function (product) {
      var newProduct = new db.Product();
      newProduct.name = product.name;
      newProduct.code = product.code;
      newProduct.tags = product.tags;
      newProduct.description = product.description;
      newProduct.save();
    });
    res.redirect("/app/products");
  } else {
    res.render("app/bulkproducts", {
      messages: { danger: "Invalid file" },
      legacy: true,
    });
  }
};

module.exports.bulkProducts = function (req, res) {
  if (req.files.products && req.files.products.mimetype == "text/xml") {
    var products = libxmljs.parseXmlString(
      req.files.products.data.toString("utf8"),
      { noent: false, noblanks: true }
    );
    products
      .root()
      .childNodes()
      .forEach((product) => {
        var newProduct = new db.Product();
        newProduct.name = product.childNodes()[0].text();
        newProduct.code = product.childNodes()[1].text();
        newProduct.tags = product.childNodes()[2].text();
        newProduct.description = product.childNodes()[3].text();
        newProduct.save();
      });
    res.redirect("/app/products");
  } else {
    res.render("app/bulkproducts", {
      messages: { danger: "Invalid file" },
      legacy: false,
    });
  }
};
